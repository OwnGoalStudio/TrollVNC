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

#import <UIKit/UIKit.h>
#import <mach/mach_time.h>
#import <objc/runtime.h>

#import "IOKitSPI.h"
#import "Logging.h"
#import "STHIDEventGenerator.h"
#import "UIScreen+Private.h"

static const NSTimeInterval fingerLiftDelay = 0.05;
static const NSTimeInterval multiTapInterval = 0.15;
static const NSTimeInterval fingerMoveInterval = 0.016;
static const NSTimeInterval longPressHoldDelay = 2.0;
static const IOHIDFloat defaultMajorRadius = 5;
static const IOHIDFloat defaultPathPressure = 0;
static const long nanosecondsPerSecond = 1e9;

static int fingerIdentifiers[] = {
    2, 3, 4, 5, 1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
};

typedef enum {
    InterpolationTypeLinear,
    InterpolationTypeSimpleCurve,
} InterpolationType;

typedef enum {
    HandEventNull,
    HandEventTouched,
    HandEventMoved,
    HandEventChordChanged,
    HandEventLifted,
    HandEventCanceled,
    StylusEventTouched,
    StylusEventMoved,
    StylusEventLifted,
} HandEventType;

typedef struct {
    int identifier;
    CGPoint point;
    IOHIDFloat pathMajorRadius;
    IOHIDFloat pathPressure;
    UInt8 pathProximity;
    BOOL isStylus;
    IOHIDFloat azimuthAngle;
    IOHIDFloat altitudeAngle;
} SyntheticEventDigitizerInfo;

NS_INLINE CFTimeInterval secondsSinceAbsoluteTime(CFAbsoluteTime startTime) {
    return (CFAbsoluteTimeGetCurrent() - startTime);
}

NS_INLINE double linearInterpolation(double a, double b, double t) { return (a + (b - a) * t); }

NS_INLINE CGPoint calculateNextLinearLocation(CGPoint a, CGPoint b, CFTimeInterval t) {
    return CGPointMake(linearInterpolation(a.x, b.x, t), linearInterpolation(a.y, b.y, t));
}

NS_INLINE double simpleCurveInterpolation(double a, double b, double t) {
    return (a + (b - a) * sin(sin(t * M_PI / 2) * t * M_PI / 2));
}

NS_INLINE CGPoint calculateNextCurveLocation(CGPoint a, CGPoint b, CFTimeInterval t) {
    return CGPointMake(simpleCurveInterpolation(a.x, b.x, t), simpleCurveInterpolation(a.y, b.y, t));
}

typedef double (*pressureInterpolationFunction)(double, double, CFTimeInterval);
static pressureInterpolationFunction availableInterpolations[] = {
    linearInterpolation,
    simpleCurveInterpolation,
};

NS_INLINE void delayBetweenMove(int eventIndex, double elapsed) {
    // Delay next event until expected elapsed time.
    double delay = (eventIndex * fingerMoveInterval) - elapsed;
    if (delay > 0) {
        struct timespec moveDelay = {0, (long)(delay * nanosecondsPerSecond)};
        nanosleep(&moveDelay, NULL);
    }
}

NS_INLINE CGFloat clampCGFloat(CGFloat v, CGFloat min, CGFloat max) { return MIN(MAX(v, min), max); }

NS_INLINE void _DTXCalcLinearPinchStartEndPoints(CGRect bounds, CGFloat pixelsScale, CGFloat angle,
                                                 CGPoint *startPoint1, CGPoint *endPoint1, CGPoint *startPoint2,
                                                 CGPoint *endPoint2) {
    *startPoint1 = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds));
    *startPoint2 = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds));

    CGFloat x = CGRectGetMinX(bounds);
    CGFloat y = CGRectGetMinY(bounds);
    CGFloat w = CGRectGetWidth(bounds);
    CGFloat h = CGRectGetHeight(bounds);

    CGFloat alpha = atan((0.5 * h) / (0.5 * w));

    if (angle <= alpha) {
        *endPoint1 = CGPointMake(x + w, CGRectGetMidY(bounds) - 0.5 * w * tan(angle));
        *endPoint2 = CGPointMake(x, CGRectGetMidY(bounds) + 0.5 * w * tan(angle));
    } else if (angle <= M_PI - alpha) {
        *endPoint1 = CGPointMake(CGRectGetMidX(bounds) + 0.5 * h * tan(M_PI_2 - angle), y);
        *endPoint2 = CGPointMake(CGRectGetMidX(bounds) - 0.5 * h * tan(M_PI_2 - angle), y + h);
    } else {
        *endPoint1 = CGPointMake(x, CGRectGetMidY(bounds) - 0.5 * w * tan(M_PI - angle));
        *endPoint2 = CGPointMake(x + w, CGRectGetMidY(bounds) + 0.5 * w * tan(M_PI - angle));
    }

    endPoint1->x = linearInterpolation(startPoint1->x, endPoint1->x, pixelsScale);
    endPoint1->y = linearInterpolation(startPoint1->y, endPoint1->y, pixelsScale);
    endPoint2->x = linearInterpolation(startPoint2->x, endPoint2->x, pixelsScale);
    endPoint2->y = linearInterpolation(startPoint2->y, endPoint2->y, pixelsScale);
}

@implementation STHIDEventGenerator {
    SyntheticEventDigitizerInfo _activePoints[HIDMaxTouchCount];
    NSUInteger _activePointCount;
    CGSize _physicalScreenSize;
    NSMutableSet<NSNumber *> *_activeKeyCodes;
    dispatch_queue_t _hidEventQueue;
    NSTimeInterval _keepAliveInterval;
    NSTimer *_keepAliveTimer;
}

+ (STHIDEventGenerator *)sharedGenerator {
    static STHIDEventGenerator *_eventGenerator = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {
            _eventGenerator = [[STHIDEventGenerator alloc] init];
        }
    });
    return _eventGenerator;
}

- (instancetype)init {
    self = [super init];
    if (!self)
        return nil;

    CGSize screenSize = [[UIScreen mainScreen] _unjailedReferenceBoundsInPixels].size;
    _physicalScreenSize = screenSize;

    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                                                         QOS_CLASS_USER_INTERACTIVE, 0);
    _hidEventQueue = dispatch_queue_create("com.82flex.trollvnc.hid-events", attr);

    for (NSUInteger i = 0; i < HIDMaxTouchCount; ++i)
        _activePoints[i].identifier = fingerIdentifiers[i];
    _activeKeyCodes = [[NSMutableSet alloc] init];

    // Default: keepAliveInterval disabled
    _keepAliveInterval = 0;
    _keepAliveTimer = nil;

    return self;
}

#pragma mark - Keep Alive Timer

- (void)_invalidateKeepAliveTimer {
    if (_keepAliveTimer) {
        [_keepAliveTimer invalidate];
        _keepAliveTimer = nil;
    }
}

- (void)_scheduleKeepAliveTimerIfNeededOnMainThread {
    if (_keepAliveInterval <= 0) {
        [self _invalidateKeepAliveTimer];
        return;
    }

    // Always recreate to apply new interval
    [self _invalidateKeepAliveTimer];

    // Schedule on main run loop to ensure timer fires reliably
    _keepAliveTimer = [NSTimer scheduledTimerWithTimeInterval:MAX(30.0, _keepAliveInterval)
                                                       target:self
                                                     selector:@selector(_keepAliveFired:)
                                                     userInfo:nil
                                                      repeats:YES];
}

- (void)_keepAliveFired:(NSTimer *)timer {
    // Fire-and-forget on background to avoid blocking main thread with nanosleep
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        [self hardwareUnlock];
        TVLog(@"KeepAlive!");
    });
}

- (NSTimeInterval)keepAliveInterval {
    @synchronized(self) {
        return _keepAliveInterval;
    }
}

- (void)setKeepAliveInterval:(NSTimeInterval)keepAliveInterval {
    @synchronized(self) {
        _keepAliveInterval = keepAliveInterval;
    }

    // Ensure timer scheduling happens on main thread
    if ([NSThread isMainThread])
        [self _scheduleKeepAliveTimerIfNeededOnMainThread];
    else
        dispatch_async(dispatch_get_main_queue(), ^{
            [self _scheduleKeepAliveTimerIfNeededOnMainThread];
        });
}

#pragma mark - HID Events

- (void)_sendIOHIDKeyboardEvent:(uint32_t)page usage:(uint32_t)usage isKeyDown:(boolean_t)isKeyDown {
    if (page != kHIDPage_Telephony) {
        uint64_t keyCode = ((uint64_t)page << 32) | usage;
        NSNumber *nsKeyCode = @(keyCode);
        if (isKeyDown) {
            [_activeKeyCodes addObject:nsKeyCode];
        } else {
            [_activeKeyCodes removeObject:nsKeyCode];
        }
    }
    [self __sendIOHIDKeyboardEvent:page usage:usage isKeyDown:isKeyDown];
}

- (void)__sendIOHIDKeyboardEvent:(uint32_t)page usage:(uint32_t)usage isKeyDown:(boolean_t)isKeyDown {
    IOHIDEventRef eventRef = IOHIDEventCreateKeyboardEvent(kCFAllocatorDefault, mach_absolute_time(), page, usage,
                                                           isKeyDown, kIOHIDEventOptionNone);
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

static IOHIDDigitizerTransducerType transducerTypeFromString(NSString *transducerTypeString) {
    if ([transducerTypeString isEqualToString:HIDEventInputTypeHand])
        return kIOHIDDigitizerTransducerTypeHand;

    if ([transducerTypeString isEqualToString:HIDEventInputTypeFinger])
        return kIOHIDDigitizerTransducerTypeFinger;

    if ([transducerTypeString isEqualToString:HIDEventInputTypeStylus])
        return kIOHIDDigitizerTransducerTypeStylus;

    abort();
    return 0;
}

static UITouchPhase phaseFromString(NSString *string) {
    if ([string isEqualToString:HIDEventPhaseBegan])
        return UITouchPhaseBegan;

    if ([string isEqualToString:HIDEventPhaseStationary])
        return UITouchPhaseStationary;

    if ([string isEqualToString:HIDEventPhaseMoved])
        return UITouchPhaseMoved;

    if ([string isEqualToString:HIDEventPhaseEnded])
        return UITouchPhaseEnded;

    if ([string isEqualToString:HIDEventPhaseCanceled])
        return UITouchPhaseCancelled;

    return UITouchPhaseStationary;
}

static InterpolationType interpolationFromString(NSString *string) {
    if ([string isEqualToString:HIDEventInterpolationTypeLinear])
        return InterpolationTypeLinear;

    if ([string isEqualToString:HIDEventInterpolationTypeSimpleCurve])
        return InterpolationTypeSimpleCurve;

    return InterpolationTypeLinear;
}

- (IOHIDDigitizerEventMask)eventMaskFromEventInfo:(NSDictionary *)info {
    IOHIDDigitizerEventMask eventMask = 0;
    NSArray<NSDictionary *> *childEvents = info[HIDEventTouchesKey];
    for (NSDictionary *touchInfo in childEvents) {
        UITouchPhase phase = phaseFromString(touchInfo[HIDEventPhaseKey]);
        // If there are any new or ended events, mask includes touch.
        if (phase == UITouchPhaseBegan || phase == UITouchPhaseEnded || phase == UITouchPhaseCancelled)
            eventMask |= kIOHIDDigitizerEventTouch;
        // If there are any pressure readings, set mask must include attribute
        if ([touchInfo[HIDEventPressureKey] doubleValue])
            eventMask |= kIOHIDDigitizerEventAttribute;
    }

    return eventMask;
}

// Returns 1 for all events where the fingers are on the glass (everything but
// ended and canceled).
- (boolean_t)isTouchFromEventInfo:(NSDictionary *)info {
    NSArray<NSDictionary *> *childEvents = info[HIDEventTouchesKey];
    for (NSDictionary *touchInfo in childEvents) {
        UITouchPhase phase = phaseFromString(touchInfo[HIDEventPhaseKey]);
        if (phase == UITouchPhaseBegan || phase == UITouchPhaseMoved || phase == UITouchPhaseStationary)
            return true;
    }

    return false;
}

- (boolean_t)isTouchFromChildEventInfo:(NSDictionary *)childInfo {
    UITouchPhase phase = phaseFromString(childInfo[HIDEventPhaseKey]);
    return (phase == UITouchPhaseBegan || phase == UITouchPhaseMoved || phase == UITouchPhaseStationary);
}

- (IOHIDEventRef)_createIOHIDEventHandReset {
    uint64_t machTime = mach_absolute_time();

    IOHIDDigitizerEventMask eventMask = kIOHIDDigitizerEventTouch;

    boolean_t isRange = false;
    boolean_t isTouching = false;

    IOHIDEventRef eventRef = IOHIDEventCreateDigitizerEvent(kCFAllocatorDefault, machTime,
                                                            kIOHIDDigitizerTransducerTypeHand, // transducerType
                                                            0,                                 // index
                                                            0,                                 // identifier
                                                            eventMask,                         // event mask
                                                            0,                                 // button event
                                                            0,                                 // x
                                                            0,                                 // y
                                                            0,                                 // z
                                                            0,                                 // presure
                                                            0,                                 // twist
                                                            isRange,                           // range
                                                            isTouching,                        // touch
                                                            kIOHIDEventOptionNone);

    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldIsBuiltIn, 1);
    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);

    return eventRef;
}

- (IOHIDEventRef)_createIOHIDEventWithInfo:(NSDictionary *)info {
    uint64_t machTime = mach_absolute_time();

    IOHIDDigitizerEventMask eventMask = [self eventMaskFromEventInfo:info];

    // isTouching == `true` if any finger is down.
    boolean_t isRange = false;
    boolean_t isTouching = [self isTouchFromEventInfo:info];

    IOHIDEventRef eventRef =
        IOHIDEventCreateDigitizerEvent(kCFAllocatorDefault, machTime,
                                       transducerTypeFromString(info[HIDEventInputType]), // transducerType
                                       0,                                                 // index
                                       0,                                                 // identifier
                                       eventMask,                                         // event mask
                                       0,                                                 // button event
                                       0,                                                 // x
                                       0,                                                 // y
                                       0,                                                 // z
                                       0,                                                 // presure
                                       0,                                                 // twist
                                       isRange,                                           // range
                                       isTouching,                                        // touch
                                       kIOHIDEventOptionNone);

    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldIsBuiltIn, 1);
    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);

    NSArray<NSDictionary *> *childEvents = info[HIDEventTouchesKey];
    for (NSDictionary *touchInfo in childEvents) {

        isTouching = [self isTouchFromChildEventInfo:touchInfo];

        IOHIDDigitizerEventMask childEventMask = [touchInfo[HIDEventMaskKey] unsignedIntValue];

        UITouchPhase phase = phaseFromString(touchInfo[HIDEventPhaseKey]);
        if (phase != UITouchPhaseCancelled && phase != UITouchPhaseBegan && phase != UITouchPhaseEnded &&
            phase != UITouchPhaseStationary)
            childEventMask |= kIOHIDDigitizerEventPosition;

        if (phase == UITouchPhaseBegan || phase == UITouchPhaseEnded || phase == UITouchPhaseCancelled)
            childEventMask |= (kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventRange);

        if (phase == UITouchPhaseCancelled)
            childEventMask |= kIOHIDDigitizerEventCancel;

        if ([touchInfo[HIDEventPressureKey] doubleValue])
            childEventMask |= kIOHIDDigitizerEventAttribute;

        int finger = 2;
        if ([touchInfo objectForKey:HIDEventFingerKey]) {
            finger = [touchInfo[HIDEventFingerKey] unsignedIntValue];
        }

        IOHIDEventRef subEvent =
            IOHIDEventCreateDigitizerFingerEvent(kCFAllocatorDefault,                              // allocator
                                                 machTime,                                         // timestamp
                                                 [touchInfo[HIDEventTouchIDKey] unsignedIntValue], // index
                                                 finger, // identifier (which finger we think it is).
                                                 childEventMask,
                                                 [touchInfo[HIDEventXKey] doubleValue],        // x
                                                 [touchInfo[HIDEventYKey] doubleValue],        // y
                                                 0,                                            // z
                                                 [touchInfo[HIDEventPressureKey] doubleValue], // pressure
                                                 [touchInfo[HIDEventTwistKey] doubleValue],    // twist
                                                 isTouching,                                   // range
                                                 isTouching,                                   // touch
                                                 kIOHIDEventOptionNone);                       // options

        IOHIDEventSetFloatValue(subEvent, kIOHIDEventFieldDigitizerMinorRadius,
                                [touchInfo[HIDEventMinorRadiusKey] doubleValue]); // minor radius
        IOHIDEventSetFloatValue(subEvent, kIOHIDEventFieldDigitizerMajorRadius,
                                [touchInfo[HIDEventMajorRadiusKey] doubleValue]); // major radius

        IOHIDEventAppendEvent(eventRef, subEvent, 0);
        CFRelease(subEvent);
    }

    return eventRef;
}

- (IOHIDEventRef)_createIOHIDEventType:(HandEventType)eventType {
    BOOL isTouching =
        (eventType == HandEventTouched || eventType == HandEventMoved || eventType == HandEventChordChanged ||
         eventType == StylusEventTouched || eventType == StylusEventMoved);

    IOHIDDigitizerEventMask eventMask = kIOHIDDigitizerEventTouch;
    if (eventType == HandEventMoved) {
        eventMask &= ~kIOHIDDigitizerEventTouch;
        eventMask |= kIOHIDDigitizerEventPosition;
        eventMask |= kIOHIDDigitizerEventAttribute;
    } else if (eventType == HandEventChordChanged) {
        eventMask |= kIOHIDDigitizerEventPosition;
        eventMask |= kIOHIDDigitizerEventAttribute;
    } else if (eventType == HandEventTouched || eventType == HandEventCanceled || eventType == HandEventLifted)
        eventMask |= kIOHIDDigitizerEventIdentity;

    uint64_t machTime = mach_absolute_time();
    IOHIDEventRef eventRef =
        IOHIDEventCreateDigitizerEvent(kCFAllocatorDefault, machTime, kIOHIDDigitizerTransducerTypeHand, 0, 0,
                                       eventMask, 0, 0, 0, 0, 0, 0, 0, isTouching, kIOHIDEventOptionNone);

    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldIsBuiltIn, 1);
    IOHIDEventSetIntegerValue(eventRef, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);

    for (NSUInteger i = 0; i < _activePointCount; ++i) {
        SyntheticEventDigitizerInfo *pointInfo = &_activePoints[i];
        if (eventType == HandEventTouched) {
            if (!pointInfo->pathMajorRadius)
                pointInfo->pathMajorRadius = defaultMajorRadius;
            if (!pointInfo->pathPressure)
                pointInfo->pathPressure = defaultPathPressure;
            if (!pointInfo->pathProximity)
                pointInfo->pathProximity = kGSEventPathInfoInTouch | kGSEventPathInfoInRange;
        } else if (eventType == HandEventLifted || eventType == HandEventCanceled || eventType == StylusEventLifted) {
            pointInfo->pathMajorRadius = 0;
            pointInfo->pathPressure = 0;
            pointInfo->pathProximity = 0;
        }

        CGPoint point = pointInfo->point;
        point = CGPointMake(point.x / _physicalScreenSize.width, point.y / _physicalScreenSize.height);

        IOHIDEventRef subEvent;
        if (pointInfo->isStylus) {
            if (eventType == StylusEventTouched) {
                eventMask |= kIOHIDDigitizerEventEstimatedAltitude;
                eventMask |= kIOHIDDigitizerEventEstimatedAzimuth;
                eventMask |= kIOHIDDigitizerEventEstimatedPressure;
            } else if (eventType == StylusEventMoved)
                eventMask = kIOHIDDigitizerEventPosition;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-anon-enum-enum-conversion"
            subEvent = IOHIDEventCreateDigitizerStylusEventWithPolarOrientation(
                kCFAllocatorDefault, machTime, pointInfo->identifier, pointInfo->identifier, eventMask, 0, point.x,
                point.y, 0, pointInfo->pathPressure, pointInfo->pathPressure, 0, pointInfo->altitudeAngle,
                pointInfo->azimuthAngle, 1, 0, isTouching ? kIOHIDTransducerTouch : kIOHIDEventOptionNone);
#pragma clang diagnostic pop

            if (eventType == StylusEventTouched)
                IOHIDEventSetIntegerValue(subEvent, kIOHIDEventFieldDigitizerWillUpdateMask, 0x0400);
            else if (eventType == StylusEventMoved)
                IOHIDEventSetIntegerValue(subEvent, kIOHIDEventFieldDigitizerDidUpdateMask, 0x0400);

        } else {
            subEvent = IOHIDEventCreateDigitizerFingerEvent(kCFAllocatorDefault,     // allocator
                                                            machTime,                // timestamp
                                                            pointInfo->identifier,   // index
                                                            pointInfo->identifier,   // identity
                                                            eventMask,               // eventMask
                                                            point.x, point.y, 0,     // x, y, z
                                                            pointInfo->pathPressure, // tipPressure
                                                            90.0,                    // twist
                                                            pointInfo->pathProximity & kGSEventPathInfoInRange, // range
                                                            pointInfo->pathProximity & kGSEventPathInfoInTouch, // touch
                                                            kIOHIDEventOptionNone);
        }

        IOHIDEventSetFloatValue(subEvent, kIOHIDEventFieldDigitizerMinorRadius,
                                pointInfo->pathMajorRadius); // minor radius
        IOHIDEventSetFloatValue(subEvent, kIOHIDEventFieldDigitizerMajorRadius,
                                pointInfo->pathMajorRadius); // major radius

        IOHIDEventAppendEvent(eventRef, subEvent, 0);
        CFRelease(subEvent);
    }

    return eventRef;
}

static void _sendHIDEvent(IOHIDEventRef eventRef, dispatch_queue_t queue) {
    static IOHIDEventSystemClientRef _ioSystemClient = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {
            _ioSystemClient = IOHIDEventSystemClientCreate(kCFAllocatorDefault);
        }
    });
    if (eventRef) {
        IOHIDEventRef strongEvent = (IOHIDEventRef)CFRetain(eventRef);
        dispatch_async(queue, ^{
            IOHIDEventSetSenderID(strongEvent, 0x8000000817319372);
            IOHIDEventSystemClientDispatchEvent(_ioSystemClient, strongEvent);

            CFRelease(strongEvent);
        });
    }
}

- (void)_updateTouchPoints:(CGPoint *)points count:(NSUInteger)count {
    NSParameterAssert(count > 0);

    HandEventType handEventType;

    // The hand event type is based on previous state.
    if (!_activePointCount)
        handEventType = HandEventTouched;
    else if (!count)
        handEventType = HandEventLifted;
    else if (count == _activePointCount)
        handEventType = HandEventMoved;
    else
        handEventType = HandEventChordChanged;

    // Update previous count for next event.
    _activePointCount = count;

    // Update point locations.
    for (NSUInteger i = 0; i < count; ++i) {
        _activePoints[i].point = points[i];
    }

    IOHIDEventRef eventRef = [self _createIOHIDEventType:handEventType];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)touchDownAtPoints:(CGPoint *)locations touchCount:(NSUInteger)touchCount {
    NSParameterAssert(touchCount > 0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);

    _activePointCount = touchCount;

    for (NSUInteger index = 0; index < touchCount; ++index) {
        _activePoints[index].point = locations[index];
        _activePoints[index].isStylus = NO;
    }

    IOHIDEventRef eventRef = [self _createIOHIDEventType:HandEventTouched];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)_touchDown:(CGPoint)location touchCount:(NSUInteger)touchCount {
    NSParameterAssert(touchCount > 0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
    CGPoint locations[touchCount];
#pragma clang diagnostic pop

    for (NSUInteger index = 0; index < touchCount; ++index)
        locations[index] = location;

    [self touchDownAtPoints:locations touchCount:touchCount];
}

- (void)touchDown:(CGPoint)location touchCount:(NSUInteger)count {
    NSParameterAssert(count > 0);

    [self _touchDown:location touchCount:count];
    [self sendMarkerHIDEvent];
}

- (void)touchDown:(CGPoint)location {
    [self touchDownAtPoints:&location touchCount:1];
    [self sendMarkerHIDEvent];
}

- (void)liftUpAtPoints:(CGPoint *)locations touchCount:(NSUInteger)touchCount {
    NSParameterAssert(touchCount > 0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);
    touchCount = MIN(touchCount, _activePointCount);

    NSUInteger newPointCount = _activePointCount - touchCount;

    for (NSUInteger index = 0; index < touchCount; ++index) {
        _activePoints[newPointCount + index].point = locations[index];
    }

    IOHIDEventRef eventRef = [self _createIOHIDEventType:HandEventLifted];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);

    _activePointCount = newPointCount;
}

- (void)_liftUp:(CGPoint)location touchCount:(NSUInteger)touchCount {
    NSParameterAssert(touchCount > 0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
    CGPoint locations[touchCount];
#pragma clang diagnostic pop

    for (NSUInteger index = 0; index < touchCount; ++index)
        locations[index] = location;

    [self liftUpAtPoints:locations touchCount:touchCount];
}

- (void)liftUp:(CGPoint)location touchCount:(NSUInteger)count {
    NSParameterAssert(count > 0);

    [self _liftUp:location touchCount:count];
    [self sendMarkerHIDEvent];
}

- (void)liftUp:(CGPoint)location {
    [self _liftUp:location touchCount:1];
    [self sendMarkerHIDEvent];
}

- (void)_moveLinearToPoints:(CGPoint *)newLocations touchCount:(NSUInteger)touchCount duration:(NSTimeInterval)seconds {
    NSParameterAssert(seconds > 0.0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
    CGPoint startLocations[touchCount];
    CGPoint nextLocations[touchCount];
#pragma clang diagnostic pop

    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();
    CFTimeInterval elapsed = 0;

    int eventIndex = 0;
    while (elapsed < (seconds - fingerMoveInterval)) {
        elapsed = secondsSinceAbsoluteTime(startTime);
        CFTimeInterval interval = elapsed / seconds;

        for (NSUInteger i = 0; i < touchCount; ++i) {
            if (!eventIndex)
                startLocations[i] = _activePoints[i].point;

            nextLocations[i] = calculateNextLinearLocation(startLocations[i], newLocations[i], interval);
        }
        [self _updateTouchPoints:nextLocations count:touchCount];

        delayBetweenMove(eventIndex++, elapsed);
    }

    [self _updateTouchPoints:newLocations count:touchCount];
}

- (void)_moveCurveToPoints:(CGPoint *)newLocations touchCount:(NSUInteger)touchCount duration:(NSTimeInterval)seconds {
    NSParameterAssert(seconds > 0.0);

    touchCount = MIN(touchCount, HIDMaxTouchCount);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
    CGPoint startLocations[touchCount];
    CGPoint nextLocations[touchCount];
#pragma clang diagnostic pop

    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();
    CFTimeInterval elapsed = 0;

    int eventIndex = 0;
    while (elapsed < (seconds - fingerMoveInterval)) {
        elapsed = secondsSinceAbsoluteTime(startTime);
        CFTimeInterval interval = elapsed / seconds;

        for (NSUInteger i = 0; i < touchCount; ++i) {
            if (!eventIndex)
                startLocations[i] = _activePoints[i].point;

            nextLocations[i] = calculateNextCurveLocation(startLocations[i], newLocations[i], interval);
        }
        [self _updateTouchPoints:nextLocations count:touchCount];

        delayBetweenMove(eventIndex++, elapsed);
    }

    [self _updateTouchPoints:newLocations count:touchCount];
}

- (void)_stylusDownAtPoint:(CGPoint)location
              azimuthAngle:(CGFloat)azimuthAngle
             altitudeAngle:(CGFloat)altitudeAngle
                  pressure:(CGFloat)pressure {
    _activePointCount = 1;
    _activePoints[0].point = location;
    _activePoints[0].isStylus = YES;

    // At the time of writing, the IOKit documentation isn't always correct. For
    // example it says that pressure is a value [0,1], but in practice it is
    // [0,500] for stylus data. It does not mention that the azimuth angle is
    // offset from a full rotation. Also, UIKit and IOHID interpret the altitude
    // as different adjacent angles.
    _activePoints[0].pathPressure = pressure * 500;
    _activePoints[0].azimuthAngle = M_PI * 2 - azimuthAngle;
    _activePoints[0].altitudeAngle = M_PI_2 - altitudeAngle;

    IOHIDEventRef eventRef = [self _createIOHIDEventType:StylusEventTouched];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)stylusDownAtPoint:(CGPoint)location
             azimuthAngle:(CGFloat)azimuthAngle
            altitudeAngle:(CGFloat)altitudeAngle
                 pressure:(CGFloat)pressure {
    [self _stylusDownAtPoint:location azimuthAngle:azimuthAngle altitudeAngle:altitudeAngle pressure:pressure];
    [self sendMarkerHIDEvent];
}

- (void)_stylusMoveToPoint:(CGPoint)location
              azimuthAngle:(CGFloat)azimuthAngle
             altitudeAngle:(CGFloat)altitudeAngle
                  pressure:(CGFloat)pressure {
    _activePointCount = 1;
    _activePoints[0].point = location;
    _activePoints[0].isStylus = YES;

    // See notes above for details on these calculations.
    _activePoints[0].pathPressure = pressure * 500;
    _activePoints[0].azimuthAngle = M_PI * 2 - azimuthAngle;
    _activePoints[0].altitudeAngle = M_PI_2 - altitudeAngle;

    IOHIDEventRef eventRef = [self _createIOHIDEventType:StylusEventMoved];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)stylusMoveToPoint:(CGPoint)location
             azimuthAngle:(CGFloat)azimuthAngle
            altitudeAngle:(CGFloat)altitudeAngle
                 pressure:(CGFloat)pressure {
    [self _stylusMoveToPoint:location azimuthAngle:azimuthAngle altitudeAngle:altitudeAngle pressure:pressure];
    [self sendMarkerHIDEvent];
}

- (void)_stylusUpAtPoint:(CGPoint)location {
    _activePointCount = 1;
    _activePoints[0].point = location;
    _activePoints[0].isStylus = YES;
    _activePoints[0].pathPressure = 0;
    _activePoints[0].azimuthAngle = 0;
    _activePoints[0].altitudeAngle = 0;

    IOHIDEventRef eventRef = [self _createIOHIDEventType:StylusEventLifted];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)stylusUpAtPoint:(CGPoint)location {
    [self _stylusUpAtPoint:location];
    [self sendMarkerHIDEvent];
}

- (void)stylusTapAtPoint:(CGPoint)location
            azimuthAngle:(CGFloat)azimuthAngle
           altitudeAngle:(CGFloat)altitudeAngle
                pressure:(CGFloat)pressure {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _stylusDownAtPoint:location azimuthAngle:azimuthAngle altitudeAngle:altitudeAngle pressure:pressure];
    nanosleep(&pressDelay, 0);
    [self _stylusUpAtPoint:location];
    [self sendMarkerHIDEvent];
}

- (void)_sendTaps:(NSUInteger)tapCount
            location:(CGPoint)location
     numberOfTouches:(NSUInteger)touchCount
    delayBetweenTaps:(NSTimeInterval)delay {
    NSParameterAssert(tapCount > 0);
    NSParameterAssert(touchCount > 0);
    NSParameterAssert(delay > 0.0);

    struct timespec doubleDelay = {0, (long)(multiTapInterval * nanosecondsPerSecond)};
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};
    BOOL useCustomDelay = delay > multiTapInterval;

    for (NSUInteger i = 0; i < tapCount; i++) {
        [self _touchDown:location touchCount:touchCount];
        nanosleep(&pressDelay, 0);
        [self _liftUp:location touchCount:touchCount];
        if (useCustomDelay) {
            struct timespec customDelay = {0, (long)(delay * nanosecondsPerSecond)};
            nanosleep(&customDelay, 0);
        } else {
            if (i + 1 != tapCount)
                nanosleep(&doubleDelay, 0);
        }
    }
}

- (void)sendTaps:(NSUInteger)tapCount
            location:(CGPoint)location
     numberOfTouches:(NSUInteger)touchCount
    delayBetweenTaps:(NSTimeInterval)delay {
    NSParameterAssert(delay > 0.0);
    [self _sendTaps:tapCount location:location numberOfTouches:touchCount delayBetweenTaps:delay];
    [self sendMarkerHIDEvent];
}

- (void)tap:(CGPoint)location {
    [self _sendTaps:1 location:location numberOfTouches:1 delayBetweenTaps:0];
    [self sendMarkerHIDEvent];
}

- (void)doubleTap:(CGPoint)location {
    [self _sendTaps:2 location:location numberOfTouches:1 delayBetweenTaps:0];
    [self sendMarkerHIDEvent];
}

- (void)twoFingerTap:(CGPoint)location {
    [self _sendTaps:1 location:location numberOfTouches:2 delayBetweenTaps:0];
    [self sendMarkerHIDEvent];
}

- (void)threeFingerTap:(CGPoint)location {
    [self _sendTaps:1 location:location numberOfTouches:3 delayBetweenTaps:0];
    [self sendMarkerHIDEvent];
}

- (void)longPress:(CGPoint)location {
    struct timespec longPressDelay = {0, (long)(longPressHoldDelay * nanosecondsPerSecond)};

    [self _touchDown:location touchCount:1];
    nanosleep(&longPressDelay, 0);
    [self _liftUp:location touchCount:1];

    [self sendMarkerHIDEvent];
}

- (void)dragLinearWithStartPoint:(CGPoint)startLocation endPoint:(CGPoint)endLocation duration:(NSTimeInterval)seconds {
    NSParameterAssert(seconds > 0.0);

    [self _touchDown:startLocation touchCount:1];
    [self _moveLinearToPoints:&endLocation touchCount:1 duration:seconds];
    [self _liftUp:endLocation touchCount:1];
    [self sendMarkerHIDEvent];
}

- (void)dragCurveWithStartPoint:(CGPoint)startLocation endPoint:(CGPoint)endLocation duration:(NSTimeInterval)seconds {
    NSParameterAssert(seconds > 0.0);

    [self _touchDown:startLocation touchCount:1];
    [self _moveCurveToPoints:&endLocation touchCount:1 duration:seconds];
    [self _liftUp:endLocation touchCount:1];
    [self sendMarkerHIDEvent];
}

- (void)_applyLinearPinchWithDuration:(NSTimeInterval)seconds
                          startPoint1:(CGPoint)startPoint1
                            endPoint1:(CGPoint)endPoint1
                          startPoint2:(CGPoint)startPoint2
                            endPoint2:(CGPoint)endPoint2 {
    NSParameterAssert(seconds > 0.0);

    CGPoint startPoints[] = {startPoint1, startPoint2};
    CGPoint endPoints[] = {endPoint1, endPoint2};

    [self touchDownAtPoints:startPoints touchCount:2];
    [self _moveLinearToPoints:endPoints touchCount:2 duration:seconds];
    [self liftUpAtPoints:endPoints touchCount:2];
    [self sendMarkerHIDEvent];
}

- (void)pinchLinearInBounds:(CGRect)bounds scale:(CGFloat)scale angle:(CGFloat)angle duration:(NSTimeInterval)seconds {
    NSParameterAssert(seconds > 0.0);
    NSParameterAssert(scale > 0.0);

    if (scale == 1.0)
        return;

    CGRect safeBounds = bounds;
    CGPoint startPoint1;
    CGPoint endPoint1;
    CGPoint startPoint2;
    CGPoint endPoint2;

    scale = clampCGFloat(scale, 0.5005, 1.9995);
    angle = fmod(angle, M_PI);
    if (angle < 0)
        angle += M_PI;

    if (scale < 1.0)
        _DTXCalcLinearPinchStartEndPoints(safeBounds, 1.0 - scale, angle, &endPoint1, &startPoint1, &endPoint2,
                                          &startPoint2);
    else
        _DTXCalcLinearPinchStartEndPoints(safeBounds, scale - 1.0, angle, &startPoint1, &endPoint1, &startPoint2,
                                          &endPoint2);

    [self _applyLinearPinchWithDuration:seconds
                            startPoint1:startPoint1
                              endPoint1:endPoint1
                            startPoint2:startPoint2
                              endPoint2:endPoint2];
}

static inline bool shouldWrapWithShiftKeyEventForCharacter(NSString *key) {
    if (key.length != 1)
        return false;
    int keyCode = [key characterAtIndex:0];
    if (65 <= keyCode && keyCode <= 90)
        return true;
    switch (keyCode) {
    case '!':
    case '@':
    case '#':
    case '$':
    case '%':
    case '^':
    case '&':
    case '*':
    case '(':
    case ')':
    case '_':
    case '+':
    case '{':
    case '}':
    case '|':
    case ':':
    case '"':
    case '<':
    case '>':
    case '?':
    case '~':
        return true;
    }
    return false;
}

static inline uint32_t keyCodeForDOMFunctionKey(NSString *key) {
    // Compare the input string with the function-key names defined by the DOM
    // spec (i.e. "F1",...,"F24"). If the input string is a function-key name, set
    // its key code. On iOS the key codes for the first 12 function keys are
    // disjoint from the key codes of the last 12 function keys.
    for (int i = 1; i <= 12; ++i) {
        if ([key isEqualToString:[NSString stringWithFormat:@"F%d", i]])
            return kHIDUsage_KeyboardF1 + i - 1;
    }
    for (int i = 13; i <= 24; ++i) {
        if ([key isEqualToString:[NSString stringWithFormat:@"F%d", i]])
            return kHIDUsage_KeyboardF13 + i - 13;
    }
    return UINT32_MAX;
}

static inline uint32_t hidUsageCodeForCharacter(NSString *key) {
    const int uppercaseAlphabeticOffset = 'A' - kHIDUsage_KeyboardA;
    const int lowercaseAlphabeticOffset = 'a' - kHIDUsage_KeyboardA;
    const int numericNonZeroOffset = '1' - kHIDUsage_Keyboard1;
    if (key.length == 1) {
        // Handle alphanumeric characters and basic symbols.
        int keyCode = [key characterAtIndex:0];
        if (97 <= keyCode && keyCode <= 122) // Handle a-z.
            return keyCode - lowercaseAlphabeticOffset;

        if (65 <= keyCode && keyCode <= 90) // Handle A-Z.
            return keyCode - uppercaseAlphabeticOffset;

        if (49 <= keyCode && keyCode <= 57) // Handle 1-9.
            return keyCode - numericNonZeroOffset;

        // Handle all other cases.
        switch (keyCode) {
        case '`':
        case '~':
            return kHIDUsage_KeyboardGraveAccentAndTilde;
        case '!':
            return kHIDUsage_Keyboard1;
        case '@':
            return kHIDUsage_Keyboard2;
        case '#':
            return kHIDUsage_Keyboard3;
        case '$':
            return kHIDUsage_Keyboard4;
        case '%':
            return kHIDUsage_Keyboard5;
        case '^':
            return kHIDUsage_Keyboard6;
        case '&':
            return kHIDUsage_Keyboard7;
        case '*':
            return kHIDUsage_Keyboard8;
        case '(':
            return kHIDUsage_Keyboard9;
        case ')':
        case '0':
            return kHIDUsage_Keyboard0;
        case '-':
        case '_':
            return kHIDUsage_KeyboardHyphen;
        case '=':
        case '+':
            return kHIDUsage_KeyboardEqualSign;
        case '\b':
            return kHIDUsage_KeyboardDeleteOrBackspace;
        case '\t':
            return kHIDUsage_KeyboardTab;
        case '[':
        case '{':
            return kHIDUsage_KeyboardOpenBracket;
        case ']':
        case '}':
            return kHIDUsage_KeyboardCloseBracket;
        case '\\':
        case '|':
            return kHIDUsage_KeyboardBackslash;
        case ';':
        case ':':
            return kHIDUsage_KeyboardSemicolon;
        case '\'':
        case '"':
            return kHIDUsage_KeyboardQuote;
        case '\r':
        case '\n':
            return kHIDUsage_KeyboardReturnOrEnter;
        case ',':
        case '<':
            return kHIDUsage_KeyboardComma;
        case '.':
        case '>':
            return kHIDUsage_KeyboardPeriod;
        case '/':
        case '?':
            return kHIDUsage_KeyboardSlash;
        case ' ':
            return kHIDUsage_KeyboardSpacebar;
        }
    }

    uint32_t keyCode;
    if ((keyCode = keyCodeForDOMFunctionKey(key)) != UINT32_MAX)
        return keyCode;

    key = [key uppercaseString];

    if ([key isEqualToString:@"CAPSLOCK"] || [key isEqualToString:@"CAPSLOCKKEY"])
        return kHIDUsage_KeyboardCapsLock;
    if ([key isEqualToString:@"PAGEUP"])
        return kHIDUsage_KeyboardPageUp;
    if ([key isEqualToString:@"PAGEDOWN"])
        return kHIDUsage_KeyboardPageDown;
    if ([key isEqualToString:@"HOME"])
        return kHIDUsage_KeyboardHome;
    if ([key isEqualToString:@"INSERT"])
        return kHIDUsage_KeyboardInsert;
    if ([key isEqualToString:@"END"])
        return kHIDUsage_KeyboardEnd;
    if ([key isEqualToString:@"ESCAPE"])
        return kHIDUsage_KeyboardEscape;
    if ([key isEqualToString:@"RETURN"] || [key isEqualToString:@"ENTER"])
        return kHIDUsage_KeyboardReturnOrEnter;
    if ([key isEqualToString:@"LEFTARROW"])
        return kHIDUsage_KeyboardLeftArrow;
    if ([key isEqualToString:@"RIGHTARROW"])
        return kHIDUsage_KeyboardRightArrow;
    if ([key isEqualToString:@"UPARROW"])
        return kHIDUsage_KeyboardUpArrow;
    if ([key isEqualToString:@"DOWNARROW"])
        return kHIDUsage_KeyboardDownArrow;
    if ([key isEqualToString:@"DELETE"] || [key isEqualToString:@"BACKSPACE"])
        return kHIDUsage_KeyboardDeleteOrBackspace;
    if ([key isEqualToString:@"FORWARDDELETE"])
        return kHIDUsage_KeyboardDeleteForward;
    if ([key isEqualToString:@"LEFTCOMMAND"] || [key isEqualToString:@"METAKEY"] || [key isEqualToString:@"COMMAND"])
        return kHIDUsage_KeyboardLeftGUI;
    if ([key isEqualToString:@"RIGHTCOMMAND"])
        return kHIDUsage_KeyboardRightGUI;
    if ([key isEqualToString:@"CLEAR"] || [key isEqualToString:@"NUMLOCK"]) // Num Lock / Clear
        return kHIDUsage_KeypadNumLock;
    if ([key isEqualToString:@"LEFTCONTROL"] || [key isEqualToString:@"CTRLKEY"] || [key isEqualToString:@"CTRL"])
        return kHIDUsage_KeyboardLeftControl;
    if ([key isEqualToString:@"RIGHTCONTROL"])
        return kHIDUsage_KeyboardRightControl;
    if ([key isEqualToString:@"LEFTSHIFT"] || [key isEqualToString:@"SHIFTKEY"] || [key isEqualToString:@"SHIFT"])
        return kHIDUsage_KeyboardLeftShift;
    if ([key isEqualToString:@"RIGHTSHIFT"])
        return kHIDUsage_KeyboardRightShift;
    if ([key isEqualToString:@"LEFTALT"] || [key isEqualToString:@"ALTKEY"] || [key isEqualToString:@"ALT"])
        return kHIDUsage_KeyboardLeftAlt;
    if ([key isEqualToString:@"RIGHTALT"])
        return kHIDUsage_KeyboardRightAlt;
    if ([key isEqualToString:@"NUMPADCOMMA"] || [key isEqualToString:@"COMMA"])
        return kHIDUsage_KeypadComma;
    if ([key isEqualToString:@"TAB"])
        return kHIDUsage_KeyboardTab;
    if ([key isEqualToString:@"SPACE"])
        return kHIDUsage_KeyboardSpacebar;
    if ([key isEqualToString:@"HYPHEN"])
        return kHIDUsage_KeyboardHyphen;
    if ([key isEqualToString:@"EQUAL"] || [key isEqualToString:@"EQUALSIGN"])
        return kHIDUsage_KeyboardEqualSign;
    if ([key isEqualToString:@"BRACKETOPEN"] || [key isEqualToString:@"OPENBRACKET"])
        return kHIDUsage_KeyboardOpenBracket;
    if ([key isEqualToString:@"BRACKETCLOSE"] || [key isEqualToString:@"CLOSEBRACKET"])
        return kHIDUsage_KeyboardCloseBracket;
    if ([key isEqualToString:@"BACKSLASH"])
        return kHIDUsage_KeyboardBackslash;
    if ([key isEqualToString:@"SEMICOLON"])
        return kHIDUsage_KeyboardSemicolon;
    if ([key isEqualToString:@"QUOTATION"] || [key isEqualToString:@"QUOTE"])
        return kHIDUsage_KeyboardQuote;
    if ([key isEqualToString:@"ACCENT"] || [key isEqualToString:@"TILDE"])
        return kHIDUsage_KeyboardGraveAccentAndTilde;
    if ([key isEqualToString:@"DOT"] || [key isEqualToString:@"PERIOD"])
        return kHIDUsage_KeyboardPeriod;
    if ([key isEqualToString:@"SLASH"])
        return kHIDUsage_KeyboardSlash;
    if ([key isEqualToString:@"PAUSE"])
        return kHIDUsage_KeyboardPause;

    // FIXME:
    // FORWARD/REWIND/FORWARD2/REWIND2/EJECT/PLAYPAUSE/SPOTLIGHT/BRIGHTUP/BRIGHTDOWN/SHOW_HIDE_KEYBOARD

    return 0;
}

- (void)keyDown:(NSString *)character {
    [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:hidUsageCodeForCharacter(character) isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)keyUp:(NSString *)character {
    [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:hidUsageCodeForCharacter(character) isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)keyPress:(NSString *)character {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};
    bool shouldWrapWithShift = shouldWrapWithShiftKeyEventForCharacter(character);
    uint32_t usage = hidUsageCodeForCharacter(character);

    if (shouldWrapWithShift)
        [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:kHIDUsage_KeyboardLeftShift isKeyDown:true];

    [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:usage isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:usage isKeyDown:false];

    if (shouldWrapWithShift)
        [self _sendIOHIDKeyboardEvent:kHIDPage_KeyboardOrKeypad usage:kHIDUsage_KeyboardLeftShift isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)dispatchHandResetEvent {
    IOHIDEventRef eventRef = [self _createIOHIDEventHandReset];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (void)dispatchEventWithInfo:(NSDictionary *)eventInfo {
    IOHIDEventRef eventRef = [self _createIOHIDEventWithInfo:eventInfo];
    _sendHIDEvent(eventRef, _hidEventQueue);
    CFRelease(eventRef);
}

- (NSArray<NSDictionary *> *)interpolatedEvents:(NSDictionary *)interpolationsDictionary {
    NSDictionary *startEvent = interpolationsDictionary[HIDEventStartEventKey];
    NSDictionary *endEvent = interpolationsDictionary[HIDEventEndEventKey];
    NSTimeInterval timeStep = [interpolationsDictionary[HIDEventTimestepKey] doubleValue];
    InterpolationType interpolationType = interpolationFromString(interpolationsDictionary[HIDEventInterpolateKey]);

    NSMutableArray<NSDictionary *> *interpolatedEvents = [NSMutableArray arrayWithObject:startEvent];

    NSTimeInterval startTime = [startEvent[HIDEventTimeOffsetKey] doubleValue];
    NSTimeInterval endTime = [endEvent[HIDEventTimeOffsetKey] doubleValue];
    NSTimeInterval time = startTime + timeStep;

    NSArray<NSDictionary *> *startTouches = startEvent[HIDEventTouchesKey];
    NSArray<NSDictionary *> *endTouches = endEvent[HIDEventTouchesKey];

    while (time < endTime) {
        NSMutableDictionary *newEvent = [endEvent mutableCopy];
        double timeRatio = (time - startTime) / (endTime - startTime);
        newEvent[HIDEventTimeOffsetKey] = @(time);

        NSEnumerator *startEnumerator = [startTouches objectEnumerator];
        NSDictionary *startTouch = nil;
        NSMutableArray<NSDictionary *> *newTouches = [NSMutableArray arrayWithCapacity:[endTouches count]];
        while (startTouch = [startEnumerator nextObject]) {
            NSEnumerator *endEnumerator = [endTouches objectEnumerator];
            NSDictionary *endTouch = [endEnumerator nextObject];
            NSInteger startTouchID = [startTouch[HIDEventTouchIDKey] integerValue];

            while (endTouch && ([endTouch[HIDEventTouchIDKey] integerValue] != startTouchID))
                endTouch = [endEnumerator nextObject];

            if (endTouch) {
                NSMutableDictionary *newTouch = [endTouch mutableCopy];

                if (newTouch[HIDEventXKey] != startTouch[HIDEventXKey])
                    newTouch[HIDEventXKey] = @(availableInterpolations[interpolationType](
                        [startTouch[HIDEventXKey] doubleValue], [endTouch[HIDEventXKey] doubleValue], timeRatio));

                if (newTouch[HIDEventYKey] != startTouch[HIDEventYKey])
                    newTouch[HIDEventYKey] = @(availableInterpolations[interpolationType](
                        [startTouch[HIDEventYKey] doubleValue], [endTouch[HIDEventYKey] doubleValue], timeRatio));

                if (newTouch[HIDEventPressureKey] != startTouch[HIDEventPressureKey])
                    newTouch[HIDEventPressureKey] = @(availableInterpolations[interpolationType](
                        [startTouch[HIDEventPressureKey] doubleValue], [endTouch[HIDEventPressureKey] doubleValue],
                        timeRatio));

                [newTouches addObject:newTouch];
            }
        }

        newEvent[HIDEventTouchesKey] = newTouches;

        [interpolatedEvents addObject:newEvent];
        time += timeStep;
    }

    [interpolatedEvents addObject:endEvent];

    return interpolatedEvents;
}

- (NSArray<NSDictionary *> *)expandEvents:(NSArray<NSDictionary *> *)events withStartTime:(CFAbsoluteTime)startTime {
    NSMutableArray<NSDictionary *> *expandedEvents = [NSMutableArray array];
    for (NSDictionary *event in events) {
        NSString *interpolate = event[HIDEventInterpolateKey];
        // we have key events that we need to generate
        if (interpolate) {
            NSArray<NSDictionary *> *newEvents = [self interpolatedEvents:event];
            [expandedEvents addObjectsFromArray:[self expandEvents:newEvents withStartTime:startTime]];
        } else
            [expandedEvents addObject:event];
    }
    return expandedEvents;
}

- (void)eventDispatchThreadEntry:(NSDictionary *)threadData {
    NSDictionary *eventStream = threadData[TopLevelEventInfoKey];

    NSArray<NSDictionary *> *events = eventStream[SecondLevelEventsKey];
    if (!events.count)
        return;

    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();

    NSArray<NSDictionary *> *expandedEvents = [self expandEvents:events withStartTime:startTime];

    for (NSDictionary *eventInfo in expandedEvents) {
        NSTimeInterval eventRelativeTime = [eventInfo[HIDEventTimeOffsetKey] doubleValue];
        CFAbsoluteTime targetTime = startTime + eventRelativeTime;

        CFTimeInterval waitTime = targetTime - CFAbsoluteTimeGetCurrent();
        if (waitTime > 0)
            STAccurateSleep(waitTime);

        [self dispatchEventWithInfo:eventInfo];
    }

    [self sendMarkerHIDEvent];
}

- (void)sendEventStream:(NSDictionary *)eventInfo {
    NSDictionary *threadData = @{TopLevelEventInfoKey : [eventInfo copy]};
    [self eventDispatchThreadEntry:threadData];
}

- (void)menuPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)menuDoublePress {
    struct timespec doubleDelay = {0, (long)(multiTapInterval * nanosecondsPerSecond)};
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:false];

    nanosleep(&doubleDelay, 0);

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)menuLongPress {
    struct timespec longPressDelay = {0, (long)(longPressHoldDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:true];
    nanosleep(&longPressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)menuDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)menuUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Menu isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)powerPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)powerDoublePress {
    struct timespec doubleDelay = {0, (long)(multiTapInterval * nanosecondsPerSecond)};
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    nanosleep(&doubleDelay, 0);

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)powerTriplePress {
    struct timespec doubleDelay = {0, (long)(multiTapInterval * nanosecondsPerSecond)};
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    nanosleep(&doubleDelay, 0);

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    nanosleep(&doubleDelay, 0);

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)powerLongPress {
    struct timespec longPressDelay = {0, (long)(longPressHoldDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    nanosleep(&longPressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)powerDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)powerUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Power isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)mutePress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Mute isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Mute isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)muteDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Mute isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)muteUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Mute isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)volumeIncrementPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeIncrement isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeIncrement isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)volumeIncrementDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeIncrement isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)volumeIncrementUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeIncrement isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)volumeDecrementPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeDecrement isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeDecrement isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)volumeDecrementDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeDecrement isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)volumeDecrementUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_VolumeDecrement isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessIncrementPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessIncrement isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessIncrement isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessIncrementDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessIncrement isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessIncrementUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessIncrement isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessDecrementPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessDecrement isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessDecrement isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessDecrementDown {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessDecrement isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)displayBrightnessDecrementUp {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_DisplayBrightnessDecrement isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)snapshotPress {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Snapshot isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_Snapshot isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)toggleOnScreenKeyboard {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ALKeyboardLayout isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ALKeyboardLayout isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)toggleSpotlight {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACSearch isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACSearch isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)otherConsumerUsagePress:(uint32_t)usage {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:usage isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:usage isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)otherConsumerUsageDown:(uint32_t)usage {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:usage isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)otherConsumerUsageUp:(uint32_t)usage {
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:usage isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)otherPage:(uint32_t)page usagePress:(uint32_t)usage {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:page usage:usage isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:page usage:usage isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)otherPage:(uint32_t)page usageDown:(uint32_t)usage {
    [self _sendIOHIDKeyboardEvent:page usage:usage isKeyDown:true];
    [self sendMarkerHIDEvent];
}

- (void)otherPage:(uint32_t)page usageUp:(uint32_t)usage {
    [self _sendIOHIDKeyboardEvent:page usage:usage isKeyDown:false];
    [self sendMarkerHIDEvent];
}

- (void)shakeIt {
}

- (void)releaseEveryKeys {
    for (NSNumber *nsKeyCode in _activeKeyCodes) {
        uint64_t keyCode = [nsKeyCode unsignedLongLongValue];
        uint32_t page = (keyCode >> 32);
        uint32_t usage = (keyCode & 0xFFFFFFFF);
        [self __sendIOHIDKeyboardEvent:page usage:usage isKeyDown:false];
    }
    [_activeKeyCodes removeAllObjects];
}

- (void)hardwareLock {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACLock isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACLock isKeyDown:false];

    [self sendMarkerHIDEvent];
}

- (void)hardwareUnlock {
    struct timespec pressDelay = {0, (long)(fingerLiftDelay * nanosecondsPerSecond)};

    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACUnlock isKeyDown:true];
    nanosleep(&pressDelay, 0);
    [self _sendIOHIDKeyboardEvent:kHIDPage_Consumer usage:kHIDUsage_Csmr_ACUnlock isKeyDown:false];

    [self sendMarkerHIDEvent];
}

#pragma mark - Marker Events

+ (CFIndex)nextEventCallbackID {
    static CFIndex callbackID = 0;
    return ++callbackID;
}

- (void)sendMarkerHIDEvent {
#if DEBUG
    CFIndex callbackID = [STHIDEventGenerator nextEventCallbackID];
    IOHIDEventRef markerEvent =
        IOHIDEventCreateVendorDefinedEvent(kCFAllocatorDefault, mach_absolute_time(), kHIDPage_VendorDefinedStart + 100,
                                           0, 1, (uint8_t *)&callbackID, sizeof(CFIndex), kIOHIDEventOptionNone);
    _sendHIDEvent(markerEvent, _hidEventQueue);
    CFRelease(markerEvent);
#endif
}

@end
