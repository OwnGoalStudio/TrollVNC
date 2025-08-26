#if !__has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag.
#endif

#import "ScreenCapturer.h"
#import "IOSurfaceSPI.h"

#import <UIKit/UIDevice.h>
#import <UIKit/UIGeometry.h>
#import <UIKit/UIImage.h>
#import <UIKit/UIScreen.h>
#import <mach/mach.h>

#if DEBUG
#define SCLog(fmt, ...) NSLog((@"%s:%d " fmt "\r"), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define SCLog(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

UIImage *_UICreateScreenUIImage(void);
CGImageRef UICreateCGImageFromIOSurface(IOSurfaceRef ioSurface);
void CARenderServerRenderDisplay(kern_return_t a, CFStringRef b, IOSurfaceRef surface, int x, int y);

#ifdef __cplusplus
}
#endif

@implementation ScreenCapturer {
    CADisplayLink *mDisplayLink;
    IOSurfaceRef mScreenSurface;
    uint32_t mSeed;
    void (^mFrameHandler)(CMSampleBufferRef sampleBuffer);
}

+ (instancetype)sharedCapturer {
    static ScreenCapturer *_inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _inst = [[self alloc] init];
    });
    return _inst;
}

+ (NSDictionary *)sharedRenderProperties {
    static NSDictionary *_renderProperties = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {

            CGRect bounds = [[UIScreen mainScreen] bounds];
            CGFloat scale = [[UIScreen mainScreen] scale];
            CGRect screenRect = CGRectMake(0, 0, round(bounds.size.width * scale), round(bounds.size.height * scale));

            // Setup the width and height of the framebuffer for the device
            int width, height;
            if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
                // iPhone frame buffer is Portrait
                width = screenRect.size.width;
                height = screenRect.size.height;
            } else {
                // iPad frame buffer is Landscape
                width = screenRect.size.height;
                height = screenRect.size.width;
            }

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

            _renderProperties = [NSDictionary
                dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:bytesPerElement], kIOSurfaceBytesPerElement,
                                             [NSNumber numberWithInt:bytesPerRow], kIOSurfaceBytesPerRow,
                                             [NSNumber numberWithInt:width], kIOSurfaceWidth,
                                             [NSNumber numberWithInt:height], kIOSurfaceHeight,
                                             [NSNumber numberWithUnsignedInt:pixelFormat], kIOSurfacePixelFormat,
                                             [NSNumber numberWithInt:bytesPerRow * height], kIOSurfaceAllocSize,
                                             CFBridgingRelease(colorSpacePropertyList), kIOSurfaceColorSpace, nil];

#if DEBUG
            SCLog(@"render properties %@", _renderProperties);
#endif
        }
    });

    return _renderProperties;
}

- (void)createScreenSurfaceIfNeeded {
    if (!mScreenSurface) {
        NSDictionary *properties = [ScreenCapturer sharedRenderProperties];
        mScreenSurface = IOSurfaceCreate((__bridge CFDictionaryRef)properties);
    }
}

+ (NSDictionary *)renderPropertiesInRect:(CGRect)rect {
    int width = (int)rect.size.width;
    int height = (int)rect.size.height;

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

    NSDictionary *properties = [NSDictionary
        dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:bytesPerElement], kIOSurfaceBytesPerElement,
                                     [NSNumber numberWithInt:bytesPerRow], kIOSurfaceBytesPerRow,
                                     [NSNumber numberWithInt:width], kIOSurfaceWidth, [NSNumber numberWithInt:height],
                                     kIOSurfaceHeight, [NSNumber numberWithUnsignedInt:pixelFormat],
                                     kIOSurfacePixelFormat, [NSNumber numberWithInt:bytesPerRow * height],
                                     kIOSurfaceAllocSize, CFBridgingRelease(colorSpacePropertyList),
                                     kIOSurfaceColorSpace, nil];

#if DEBUG
    SCLog(@"render properties %@", properties);
#endif

    return properties;
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

- (BOOL)writeScreenUIImagePNGDataToFile:(NSString *)path {
    return [[self getScreenUIImagePNGData] writeToFile:path atomically:YES];
}

#pragma mark - Rendering

- (void)renderDisplayToScreenSurface:(IOSurfaceRef)dstSurface {
    CFRunLoopRef runLoop = CFRunLoopGetMain();

    static IOSurfaceRef srcSurface;
    static IOSurfaceAcceleratorRef accelerator;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {
            srcSurface = IOSurfaceCreate((__bridge CFDictionaryRef)[ScreenCapturer sharedRenderProperties]);
            IOSurfaceAcceleratorCreate(kCFAllocatorDefault, nil, &accelerator);

            CFRunLoopSourceRef runLoopSource = IOSurfaceAcceleratorGetRunLoopSource(accelerator);
            CFRunLoopAddSource(runLoop, runLoopSource, kCFRunLoopDefaultMode);
        }
    });

    /// Fast ~20ms, sRGB, while the image is GOOD. Recommended.
    CARenderServerRenderDisplay(0, CFSTR("LCD"), srcSurface, 0, 0);
    IOSurfaceAcceleratorTransformSurface(accelerator, srcSurface, dstSurface, NULL, NULL, NULL, NULL, NULL);
}

- (void)updateDisplay {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    [self createScreenSurfaceIfNeeded];

    // Lock the surface
    IOSurfaceLock(mScreenSurface, 0, &mSeed);

    [self renderDisplayToScreenSurface:mScreenSurface];

    // Unlock the surface
    IOSurfaceUnlock(mScreenSurface, 0, &mSeed);

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    static double s_lastLogAtMs = 0.0;
    double nowMs = (double)endAt / NSEC_PER_MSEC;
    if (nowMs - s_lastLogAtMs >= 2000.0) { // log at most once every 2 seconds
        double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
        SCLog(@"time elapsed %.2fms, %zu bytes memory used", used, [ScreenCapturer __getMemoryUsedInBytes]);
        s_lastLogAtMs = nowMs;
    }
#endif
}

- (IOSurfaceRef)copyScreenSurface {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)[ScreenCapturer sharedRenderProperties]);

    // Lock the surface
    IOSurfaceLock(surface, 0, &mSeed);

    [self renderDisplayToScreenSurface:surface];

    // Unlock the surface
    IOSurfaceUnlock(surface, 0, &mSeed);

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms", used);
#endif

    return surface;
}

- (CGImageRef)copyScreenCGImage {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    NSDictionary *screenProperties = [ScreenCapturer sharedRenderProperties];

    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)screenProperties);

    // Lock the surface
    IOSurfaceLock(surface, 0, &mSeed);

    [self renderDisplayToScreenSurface:surface];

    // Make a raw memory copy of the surface
    void *baseAddr = IOSurfaceGetBaseAddress(surface);
    size_t allocSize = IOSurfaceGetAllocSize(surface);

    CFDataRef rawData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)baseAddr, allocSize);
    CGDataProviderRef dataProvider = CGDataProviderCreateWithCFData(rawData);

    int width = [screenProperties[(__bridge NSString *)kIOSurfaceWidth] intValue];
    int height = [screenProperties[(__bridge NSString *)kIOSurfaceHeight] intValue];
    int bytesPerRow = [screenProperties[(__bridge NSString *)kIOSurfaceBytesPerRow] intValue];
    int bytesPerComponent = sizeof(uint8_t);
    int bytesPerElement = [screenProperties[(__bridge NSString *)kIOSurfaceBytesPerElement] intValue];

    CGColorSpaceRef colorSpace =
        CGColorSpaceCreateWithName((__bridge CFStringRef)screenProperties[(__bridge NSString *)kIOSurfaceColorSpace]);

    CGImageRef cgImage = CGImageCreate(width, height, bytesPerComponent * BYTE_SIZE, bytesPerElement * BYTE_SIZE,
                                       bytesPerRow /* already aligned */, colorSpace,
                                       kCGBitmapByteOrder32Little | (CGBitmapInfo)kCGImageAlphaPremultipliedFirst, dataProvider, NULL, NO,
                                       kCGRenderingIntentDefault);

    CGDataProviderRelease(dataProvider);
    CGColorSpaceRelease(colorSpace);
    CFRelease(rawData);

    // Unlock and release the surface
    IOSurfaceUnlock(surface, 0, &mSeed);
    CFRelease(surface);

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms", used);
#endif
    return cgImage;
}

- (UIImage *)getScreenUIImage {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    UIImage *uiImage = _UICreateScreenUIImage();

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms", used);
#endif

    return uiImage;
}

- (NSData *)getScreenUIImagePNGData {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif
    // coding is slow: ~200ms
    NSData *data = UIImagePNGRepresentation([self getScreenUIImage]);
#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms", used);
#endif
    return data;
}

#pragma mark - Transfer

- (NSData *)getScreenUIImageRAWDataNoCopy {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    [self createScreenSurfaceIfNeeded];
    [self updateDisplay];

    void *baseAddr = IOSurfaceGetBaseAddress(mScreenSurface);
    size_t allocSize = IOSurfaceGetAllocSize(mScreenSurface);
    NSData *data = nil;

    if (baseAddr && allocSize > 0) {
        data = [NSData dataWithBytesNoCopy:baseAddr length:allocSize freeWhenDone:NO];
    } else {
        data = [NSData data];
    }

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms, %zu bytes memory used", used, [ScreenCapturer __getMemoryUsedInBytes]);
#endif

    return data;
}

#pragma mark - Remote Client

- (void)transferDisplayToSharedScreenSurface {
    [self createScreenSurfaceIfNeeded];
    [self transferDisplayToScreenSurface:mScreenSurface];
}

- (void)transferDisplayToScreenSurface:(IOSurfaceRef)surface {
#if DEBUG
    __uint64_t beginAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif

    // Lock the surface
    IOSurfaceLock(surface, 0, &mSeed);

    NSData *replyData = [self getScreenUIImageRAWDataNoCopy];
    void *baseAddr = IOSurfaceGetBaseAddress(surface);
    size_t allocSize = IOSurfaceGetAllocSize(surface);

    if ([replyData isKindOfClass:[NSData class]]) {
        memcpy(baseAddr, replyData.bytes, MIN(replyData.length, allocSize));
    } else {
        bzero(baseAddr, allocSize);
    }

    // Unlock the surface
    IOSurfaceUnlock(surface, 0, &mSeed);

#if DEBUG
    __uint64_t endAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    double used = (double)(endAt - beginAt) / NSEC_PER_MSEC;
    SCLog(@"time elapsed %.2fms, %zu bytes memory used", used, [ScreenCapturer __getMemoryUsedInBytes]);
#endif
}

#pragma mark - Public Methods

- (void)startCaptureWithFrameHandler:(void (^)(CMSampleBufferRef _Nonnull))frameHandler {
    // Store/replace handler
    mFrameHandler = [frameHandler copy];

    if (mDisplayLink) {
        // Already running; nothing else to do
        return;
    }

    // Ensure surface exists before first tick
    [self createScreenSurfaceIfNeeded];

    // Create display link on main run loop
    void (^startBlock)(void) = ^{
        mDisplayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(onDisplayLink:)];
#if defined(__IPHONE_10_3) && (__IPHONE_OS_VERSION_MAX_ALLOWED >= __IPHONE_10_3)
        if ([mDisplayLink respondsToSelector:@selector(preferredFramesPerSecond)]) {
            mDisplayLink.preferredFramesPerSecond = 0; // Use native
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

        if (mScreenSurface) {
            CFRelease(mScreenSurface);
            mScreenSurface = nil;
        }
    };

    if ([NSThread isMainThread]) {
        stopBlock();
    } else {
        dispatch_async(dispatch_get_main_queue(), stopBlock);
    }
}

// MARK: - Private

- (void)onDisplayLink:(CADisplayLink *)link {
    if (!mFrameHandler)
        return;

    // Update the screen contents into our IOSurface
    [self updateDisplay];

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
