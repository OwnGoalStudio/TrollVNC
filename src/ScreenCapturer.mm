/*
 This file is part of TrollVNC
 Copyright (c) 2025 82Flex <82flex@gmail.com> and contributors

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License version 2
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#if !__has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag.
#endif

#import <UIKit/UIDevice.h>
#import <UIKit/UIGeometry.h>
#import <UIKit/UIImage.h>
#import <UIKit/UIScreen.h>
#import <mach/mach.h>

#import "Control.h"
#import "IOKitSPI.h"
#import "IOSurfaceSPI.h"
#import "Logging.h"
#import "ScreenCapturer.h"
#import "UIScreen+Private.h"

#ifdef __cplusplus
extern "C" {
#endif

CFIndex CARenderServerGetDirtyFrameCount(void *);
void CARenderServerRenderDisplay(kern_return_t a, CFStringRef b, IOSurfaceRef surface, int x, int y);

#ifdef __cplusplus
}
#endif

@implementation ScreenCapturer {
    NSDictionary *mRenderProperties;
    IOSurfaceRef mScreenSurface;
    CADisplayLink *mDisplayLink;
    void (^mFrameHandler)(CMSampleBufferRef sampleBuffer);
    NSInteger mMinFps;
    NSInteger mPreferredFps;
    NSInteger mMaxFps;
    // Stats configuration (effective in DEBUG only)
    NSTimeInterval mStatsWindowSeconds; // average FPS logging window
    double mInstFpsAlpha;               // EMA smoothing factor for instantaneous FPS
}

+ (instancetype)sharedCapturer {
    static ScreenCapturer *_inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _inst = [[self alloc] init];
        // Defaults for stats logging
#if DEBUG
        [_inst setStatsLogWindowSeconds:5.0];
        [_inst setInstantFpsSmoothingFactor:0.2];
#endif
    });
    return _inst;
}

- (instancetype)init {
    self = [super init];
    if (!self)
        return nil;

    int width, height;
    CGSize screenSize = [[UIScreen mainScreen] _unjailedReferenceBoundsInPixels].size;

#if !TARGET_IPHONE_SIMULATOR
    if (gShouldApplyOrientationFix) {
        width = (int)round(screenSize.height);
        height = (int)round(screenSize.width);
    } else {
#endif
        width = (int)round(screenSize.width);
        height = (int)round(screenSize.height);
#if !TARGET_IPHONE_SIMULATOR
    }
#endif

    // Pixel format for Alpha, Red, Green and Blue
    unsigned pixelFormat = 0x42475241; // 'ARGB'

    // 1 or 2 bytes per component
    int bytesPerComponent = sizeof(uint8_t);

    // 8 bytes per pixel
    int bytesPerElement = bytesPerComponent * 4;

    // Bytes per row (must be aligned)
    int bytesPerRow = (int)IOSurfaceAlignProperty(kIOSurfaceBytesPerRow, bytesPerElement * width);

    // Properties included:
    // BytesPerElement, BytesPerRow, Width, Height, PixelFormat, AllocSize
    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);

    CFPropertyListRef colorSpacePropertyList = CGColorSpaceCopyPropertyList(colorSpace);
    CGColorSpaceRelease(colorSpace);

    mRenderProperties = @{
        (__bridge NSString *)kIOSurfaceBytesPerElement : @(bytesPerElement),
        (__bridge NSString *)kIOSurfaceBytesPerRow : @(bytesPerRow),
        (__bridge NSString *)kIOSurfaceWidth : @(width),
        (__bridge NSString *)kIOSurfaceHeight : @(height),
        (__bridge NSString *)kIOSurfacePixelFormat : @(pixelFormat),
        (__bridge NSString *)kIOSurfaceAllocSize : @(bytesPerRow * height),
        (__bridge NSString *)kIOSurfaceColorSpace : CFBridgingRelease(colorSpacePropertyList),
    };

#if DEBUG
    TVLog(@"render properties %@", mRenderProperties);
#endif

    mScreenSurface = IOSurfaceCreate((__bridge CFDictionaryRef)mRenderProperties);
    mDisplayLink = nil;
    mFrameHandler = NULL;
    mMinFps = 0;
    mPreferredFps = 0;
    mMaxFps = 0;
    mStatsWindowSeconds = 0.0;
    mInstFpsAlpha = 0.0;

    return self;
}

#pragma mark - Testing

+ (unsigned long)__getMemoryUsedInBytes {
    struct task_basic_info info;
    mach_msg_type_number_t size = sizeof(info);
    kern_return_t kerr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &size);
    if (kerr == KERN_SUCCESS) {
        return info.resident_size;
    } else {
        return 0;
    }
}

// Human-readable memory usage description based on __getMemoryUsedInBytes
+ (NSString *)_getMemoryUsageDescription {
    long long bytes = (long long)[self __getMemoryUsedInBytes];
    return [NSByteCountFormatter stringFromByteCount:bytes countStyle:NSByteCountFormatterCountStyleBinary];
}

#pragma mark - Rendering

static CFIndex sDirtyFrameCount = 0;

- (BOOL)renderDisplayToScreenSurface:(IOSurfaceRef)dstSurface {
#if TARGET_OS_SIMULATOR
    CARenderServerRenderDisplay(0, CFSTR("LCD"), dstSurface, 0, 0);
    return YES; // Assume always changed: dirty detection does not work for simulator
#else
    CFRunLoopRef runLoop = CFRunLoopGetMain();

    static IOSurfaceRef srcSurface;
    static IOSurfaceAcceleratorRef accelerator;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {
            srcSurface = IOSurfaceCreate((__bridge CFDictionaryRef)mRenderProperties);
            IOSurfaceAcceleratorCreate(kCFAllocatorDefault, nil, &accelerator);

            CFRunLoopSourceRef runLoopSource = IOSurfaceAcceleratorGetRunLoopSource(accelerator);
            CFRunLoopAddSource(runLoop, runLoopSource, kCFRunLoopDefaultMode);
        }
    });

    CFIndex dirtyFrameCount = CARenderServerGetDirtyFrameCount(NULL);
    if (dirtyFrameCount == sDirtyFrameCount) {
        return NO; // No change
    }

    // Fast ~20ms, sRGB, while the image is GOOD. Recommended.
    CARenderServerRenderDisplay(0 /* Main Display */, CFSTR("LCD"), srcSurface, 0, 0);
    IOSurfaceAcceleratorTransferSurface(accelerator, srcSurface, dstSurface, NULL, NULL, NULL, NULL);

    sDirtyFrameCount = dirtyFrameCount;
    return YES;
#endif
}

- (BOOL)updateDisplay:(CADisplayLink *)displayLink {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    BOOL surfaceChanged = [self renderDisplayToScreenSurface:mScreenSurface];

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    static double sLastLogAtMs = 0.0;
    static __uint64_t sFpsWindowStartNs = 0;  // FPS window start (ns)
    static unsigned long long sFpsFrames = 0; // Accumulated frames in window
    static double sInstFpsEma = 0.0;          // Smoothed instantaneous FPS (EMA)

    // Accumulate frame count
    if (surfaceChanged) {
        sFpsFrames++;
    }
    if (sFpsWindowStartNs == 0) {
        sFpsWindowStartNs = endAt;
    }

    // Instantaneous FPS sourced from CADisplayLink.duration; fallback to inter-frame delta if needed
    double instFps = 0.0;
    CFTimeInterval duration = displayLink.duration;
    if (duration > 0.0) {
        instFps = 1.0 / duration;
    }

    double nowMs = (double)endAt / NSEC_PER_MSEC;

    // EMA smoothing for instantaneous FPS
    if (instFps > 0.0) {
        double alpha = mInstFpsAlpha;
        sInstFpsEma = (sInstFpsEma == 0.0) ? instFps : (alpha * instFps + (1.0 - alpha) * sInstFpsEma);
    }

    // Periodic logging based on configurable window
    double windowMs = (mStatsWindowSeconds > 0.0) ? (mStatsWindowSeconds * 1000.0) : 0.0;
    if (windowMs > 0.0 && (nowMs - sLastLogAtMs >= windowMs)) {
        double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
        double windowSec = (double)(endAt - sFpsWindowStartNs) / 1e9; // ns -> s
        double fps = (windowSec > 0.0) ? (sFpsFrames / windowSec) : 0.0;
        double instOut = (sInstFpsEma > 0.0) ? sInstFpsEma : instFps;

        TVLog(@"elapsed %.2fms, real fps %.2f (frames=%llu, window=%.2fs), inst fps %.2f, memory used %@", used, fps,
              sFpsFrames, windowSec, instOut, [ScreenCapturer _getMemoryUsageDescription]);

        sLastLogAtMs = nowMs;

        // Reset FPS window
        sFpsWindowStartNs = endAt;
        sFpsFrames = 0;
        sInstFpsEma = 0.0;
    }
#endif

    return surfaceChanged;
}

#pragma mark - Public Methods

- (NSDictionary *)renderProperties {
    return mRenderProperties;
}

- (void)startCaptureWithFrameHandler:(void (^)(CMSampleBufferRef _Nonnull))frameHandler {
    // Store/replace handler
    mFrameHandler = [frameHandler copy];

    if (mDisplayLink) {
        // Already running; nothing else to do
        return;
    }

    // Create display link on main run loop
    void (^startBlock)(void) = ^{
        mDisplayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(onDisplayLink:)];

#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 150000
        if (@available(iOS 15.0, *)) {
            CAFrameRateRange range;
            range.minimum = (mMinFps > 0) ? mMinFps : 0.0;
            range.maximum = (mMaxFps > 0) ? mMaxFps : 0.0;
            range.preferred = (mPreferredFps > 0) ? mPreferredFps : 0.0;
            mDisplayLink.preferredFrameRateRange = range;
        } else {
#endif
            // iOS 14 fallback: use preferredFramesPerSecond; choose max in the provided range
            NSInteger setFps = (mMaxFps > 0) ? mMaxFps : mPreferredFps;
            if ([mDisplayLink respondsToSelector:@selector(preferredFramesPerSecond)])
                mDisplayLink.preferredFramesPerSecond = (int)setFps; // 0 uses native/system default
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 150000
        }
#endif

        [mDisplayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
    };

    if ([NSThread isMainThread]) {
        startBlock();
    } else {
        dispatch_async(dispatch_get_main_queue(), startBlock);
    }
}

- (void)endCapture {
    void (^stopBlock)(void) = ^{
        if (mDisplayLink) {
            [mDisplayLink invalidate];
            mDisplayLink = nil;
        }
        mFrameHandler = nil;
    };

    if ([NSThread isMainThread]) {
        stopBlock();
    } else {
        dispatch_async(dispatch_get_main_queue(), stopBlock);
    }
}

- (void)setPreferredFrameRateWithMin:(NSInteger)minFps preferred:(NSInteger)preferredFps max:(NSInteger)maxFps {
    // Normalize: if preferred is 0, but max/min provided, pick a reasonable default
    mMinFps = MAX(0, minFps);
    mMaxFps = MAX(0, maxFps);
    mPreferredFps = MAX(0, preferredFps);

    if (mPreferredFps == 0) {
        if (mMaxFps > 0)
            mPreferredFps = mMaxFps;
        else if (mMinFps > 0)
            mPreferredFps = mMinFps;
        else
            mPreferredFps = 0;
    }

    // If display link is already running, update it on main thread
    if (mDisplayLink) {
        void (^applyBlock)(void) = ^{
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 150000
            if (@available(iOS 15.0, *)) {
                CAFrameRateRange range;
                range.minimum = (mMinFps > 0) ? mMinFps : 0.0;
                range.maximum = (mMaxFps > 0) ? mMaxFps : 0.0;
                range.preferred = (mPreferredFps > 0) ? mPreferredFps : 0.0;
                mDisplayLink.preferredFrameRateRange = range;
            } else {
#endif
                // iOS 14 path: only preferredFramesPerSecond is available, use max/preferred
                NSInteger setFps = (mMaxFps > 0) ? mMaxFps : mPreferredFps;
                mDisplayLink.preferredFramesPerSecond = (int)setFps; // 0 means system default
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 150000
            }
#endif
        };

        if ([NSThread isMainThread])
            applyBlock();
        else
            dispatch_async(dispatch_get_main_queue(), applyBlock);
    }
}

- (void)setStatsLogWindowSeconds:(NSTimeInterval)seconds {
    mStatsWindowSeconds = seconds;
}

- (void)setInstantFpsSmoothingFactor:(double)alpha {
    if (alpha < 0.0)
        alpha = 0.0;
    if (alpha > 1.0)
        alpha = 1.0;
    mInstFpsAlpha = alpha;
}

- (void)forceNextFrameUpdate {
    sDirtyFrameCount = 0; // Force next frame to be treated as dirty
}

#pragma mark - Private Methods

- (void)onDisplayLink:(CADisplayLink *)link {
    if (!mFrameHandler)
        return;

    // Update the screen contents into our IOSurface
    BOOL displayChanged = [self updateDisplay:link];
    if (!displayChanged) {
        return; // No change, nothing to do
    }

    // Wrap IOSurface in a CVPixelBuffer (zero-copy)
    CVPixelBufferRef pixelBuffer = NULL;
    NSDictionary *attrs = @{(NSString *)kCVPixelBufferIOSurfacePropertiesKey : @{}};
    CVReturn cvret = CVPixelBufferCreateWithIOSurface(kCFAllocatorDefault, mScreenSurface,
                                                      (__bridge CFDictionaryRef)attrs, &pixelBuffer);
    if (cvret != kCVReturnSuccess || !pixelBuffer) {
        return;
    }

    // Create format description from the pixel buffer
    CMVideoFormatDescriptionRef formatDesc = NULL;
    OSStatus status = CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, pixelBuffer, &formatDesc);
    if (status != noErr || !formatDesc) {
        CVPixelBufferRelease(pixelBuffer);
        return;
    }

    // Build timing from CADisplayLink
    int32_t timescale = 1000000000; // 1 ns
    CMSampleTimingInfo timing;
    timing.duration = CMTimeMakeWithSeconds(link.duration, timescale);
    timing.presentationTimeStamp = CMTimeMakeWithSeconds(link.timestamp, timescale);
    timing.decodeTimeStamp = kCMTimeInvalid;

    CMSampleBufferRef sampleBuffer = NULL;
    status = CMSampleBufferCreateForImageBuffer(kCFAllocatorDefault, pixelBuffer, true, NULL, NULL, formatDesc, &timing,
                                                &sampleBuffer);

    if (status == noErr && sampleBuffer) {
        mFrameHandler(sampleBuffer);
        CFRelease(sampleBuffer);
    }

    if (formatDesc)
        CFRelease(formatDesc);
    if (pixelBuffer)
        CVPixelBufferRelease(pixelBuffer);
}

@end
