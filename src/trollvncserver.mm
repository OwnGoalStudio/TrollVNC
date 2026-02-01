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

#import <Accelerate/Accelerate.h>
#import <Foundation/Foundation.h>

#import <arpa/inet.h>
#import <atomic>
#import <climits>
#import <cstdio>
#import <cstdlib>
#import <cstring>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <netinet/in.h>
#import <pthread.h>
#import <rfb/keysym.h>
#import <rfb/rfb.h>
#import <string>
#import <sys/socket.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <vector>

#import "BulletinManager.h"
#import "ClipboardManager.h"
#import "Control.h"
#import "FBSOrientationObserver.h"
#import "IOKitSPI.h"
#import "Logging.h"
#import "PSAssistiveTouchSettingsDetail.h"
#import "STHIDEventGenerator.h"
#import "ScreenCapturer.h"

#define LocalizedString(key, comment, bundle, table)                                                                   \
    (NSLocalizedStringFromTableInBundle((key), (table), (bundle), (comment)) ?: (key))

#define TVPrintError(fmt, ...)                                                                                         \
    do {                                                                                                               \
        fprintf(stderr, fmt "\r\n", ##__VA_ARGS__);                                                                    \
    } while (0)

#pragma mark - Options

BOOL gShouldApplyOrientationFix = NO; // set to YES to enable iPad orientation fix

static BOOL gEnabled = YES;
static int gPort = 5901;
static int gTvCtlPort = 0;        // port for control connections (0 = disabled)
static NSString *gBindHost = nil; // optional bind address from CLI/config
static NSString *gDesktopName = @"TrollVNC";
static BOOL gViewOnly = NO;
static double gKeepAliveSec = 0.0; // 15..86400
static BOOL gClipboardEnabled = YES;
static BOOL gIsDaemonMode = NO; // set when launched with -daemon

static double gScale = 1.0; // 0 < scale <= 1.0, 1.0 = no scaling
// Preferred frame rate range (0 = unspecified)
static int gFpsMin = 0;
static int gFpsPref = 0;
static int gFpsMax = 0;
static double gDeferWindowSec = 0.015;      // Coalescing window; 0 disables deferral
static int gMaxInflightUpdates = 2;         // Max concurrent client encodes; drop frames if >= this
static int gTileSize = 32;                  // Tile size for dirty detection (pixels)
static int gFullscreenThresholdPercent = 0; // If changed tiles exceed this %, update full screen
static int gMaxRectsLimit = 256;            // Max rects before falling back to bbox/fullscreen
static BOOL gAsyncSwapEnabled = NO;         // Enable non-blocking swap (may cause tearing)

// Wheel scroll coalescing state (async, non-blocking)
static double gWheelStepPx = 48.0;        // base pixels per wheel tick (lower = slower)
static double gWheelMaxStepPx = 192.0;    // base max distance per flush (pre-clamp)
static double gWheelCoalesceSec = 0.03;   // coalescing window
static double gWheelAbsClampFactor = 2.5; // absolute clamp = factor * gWheelMaxStepPx
static double gWheelAmpCoeff = 0.18;      // velocity amplification coefficient
static double gWheelAmpCap = 0.75;        // max extra amplification (0..1)
static double gWheelMinTakeRatio = 0.35;  // minimum take distance vs step size
static double gWheelDurBase = 0.05;       // duration base seconds
static double gWheelDurK = 0.00016;       // duration factor applied to sqrt(distance)
static double gWheelDurMin = 0.05;        // duration clamp min
static double gWheelDurMax = 0.14;        // duration clamp max
static BOOL gWheelNaturalDir = NO;        // natural scroll direction (invert delta)

// Modifier mapping scheme: 0 = standard (Alt->Option, Meta/Super->Command), 1 = Alt-as-Command
static int gModMapScheme = 0;
static BOOL gAutoAssistEnabled = NO;
static BOOL gCursorEnabled = NO;
static BOOL gKeyEventLogging = NO;
static BOOL gOrientationSyncEnabled = YES;

// Classic VNC authentication
static char **gAuthPasswdVec = NULL;        // owns the vector
static char *gAuthPasswdStr = NULL;         // owns the duplicated password string
static char *gAuthViewOnlyPasswdStr = NULL; // optional view-only password string

// HTTP server (LibVNCServer built-in web client)
static int gHttpPort = 0;
static char *gHttpDirOverride = NULL;
static char *gSslCertPath = NULL;
static char *gSslKeyPath = NULL;

// Bonjour / mDNS Auto-Discovery
static BOOL gBonjourEnabled = YES; // publish _rfb._tcp (and optional _http._tcp)

// TightVNC 1.x file transfer extension (deprecated)
static BOOL gFileTransferEnabled = NO;

// UltraVNC repeater
static int gRepeaterMode = 0; // 0: disabled, 1: viewer, 2: repeater
static char *gRepeaterHost = NULL;
static int gRepeaterPort = 5500;
static int gRepeaterId = 12345679;

// User notifications
static BOOL gUserClientNotifsEnabled = YES;
static BOOL gUserSingleNotifsEnabled = YES;

// Blocked hosts (temporary blacklist)
static NSMutableSet<NSString *> *gBlockedHosts = nil;

typedef NS_ENUM(uint8_t, TVBindHostKind) {
    kTVBindHostKindNone = 0,
    kTVBindHostKindIPv4,
    kTVBindHostKindIPv6,
    kTVBindHostKindInvalid,
};

static TVBindHostKind tvClassifyBindHost(NSString *host, in_addr_t *outIPv4, struct in6_addr *outIPv6) {
    if (outIPv4)
        *outIPv4 = 0;
    if (outIPv6)
        memset(outIPv6, 0, sizeof(*outIPv6));

    if (!host || host.length == 0)
        return kTVBindHostKindNone;

    const char *cstr = [host UTF8String];
    if (!cstr || *cstr == '\0')
        return kTVBindHostKindNone;

    struct in_addr v4;
    if (inet_pton(AF_INET, cstr, &v4) == 1) {
        if (outIPv4)
            *outIPv4 = v4.s_addr;
        return kTVBindHostKindIPv4;
    }

    char addrBuf[INET6_ADDRSTRLEN + 1];
    const char *pct = strchr(cstr, '%');
    size_t copyLen = pct ? (size_t)(pct - cstr) : strlen(cstr);
    if (copyLen >= sizeof(addrBuf))
        copyLen = sizeof(addrBuf) - 1;
    memcpy(addrBuf, cstr, copyLen);
    addrBuf[copyLen] = '\0';

    struct in6_addr v6;
    if (inet_pton(AF_INET6, addrBuf, &v6) == 1) {
        if (outIPv6)
            *outIPv6 = v6;
        return kTVBindHostKindIPv6;
    }

    return kTVBindHostKindInvalid;
}

NS_INLINE BOOL isRepeaterEnabled(void) {
    return gRepeaterMode > 0 && gRepeaterHost != NULL && gRepeaterHost[0] != '\0' && gRepeaterPort > 0;
}

#pragma mark - Bundle

static NSString *tvExecutablePath(void) {
    static NSString *sPath = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Resolve executable path
        uint32_t sz = 0;
        _NSGetExecutablePath(NULL, &sz); // query size
        char *exeBuf = (char *)malloc(sz > 0 ? sz : PATH_MAX);
        if (!exeBuf)
            return;
        if (_NSGetExecutablePath(exeBuf, &sz) != 0) {
            // Fallback: leave exeBuf as-is
        }

        // Canonicalize
        char realBuf[PATH_MAX];
        const char *exePath = realpath(exeBuf, realBuf) ? realBuf : exeBuf;
        NSString *exe = [NSString stringWithUTF8String:exePath ? exePath : ""];
        free(exeBuf);

        sPath = exe ?: [[NSProcessInfo processInfo] arguments][0];
    });
    return sPath;
}

static NSBundle *tvResourceBundle(void) {
    static NSBundle *sBundle = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
#ifdef THEBOOTSTRAP
        NSString *exe = tvExecutablePath();
        NSString *dir = [exe stringByDeletingLastPathComponent];
        NSBundle *mainBundle = [NSBundle bundleWithPath:dir];
        if (!mainBundle)
            return;

        NSString *resPath = [mainBundle pathForResource:@"TrollVNCPrefs" ofType:@"bundle"];
        NSBundle *resBundle = resPath ? [NSBundle bundleWithPath:resPath] : nil;
        if (!resBundle)
            return;

        sBundle = resBundle;
#else
        NSString *exe = tvExecutablePath();
        NSString *exeDir = [exe stringByDeletingLastPathComponent];
        NSString *resRel = @"../../Library/PreferenceBundles/TrollVNCPrefs.bundle";
        NSString *resPath = [[exeDir stringByAppendingPathComponent:resRel] stringByStandardizingPath];
        NSBundle *resBundle = resPath ? [NSBundle bundleWithPath:resPath] : nil;
        if (!resBundle)
            return;

        sBundle = resBundle;
#endif
    });
    return sBundle;
}

static NSBundle *tvLocalizationBundle(void) {
    static NSBundle *sBundle = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *resBundle = tvResourceBundle();

        NSArray<NSString *> *languages =
            [[NSUserDefaults standardUserDefaults] objectForKey:@"AppleLanguages"] ?: @"en";

        NSString *localizablePath = nil;
        for (NSString *localization in [NSBundle preferredLocalizationsFromArray:[resBundle localizations]
                                                                  forPreferences:languages]) {
            localizablePath = [resBundle pathForResource:@"Localizable"
                                                  ofType:@"strings"
                                             inDirectory:nil
                                         forLocalization:localization];
            if (localizablePath && localizablePath.length > 0)
                break;
        }

        NSString *lprojPath = [localizablePath stringByDeletingLastPathComponent];
        if (lprojPath && lprojPath.length > 0) {
            resBundle = [NSBundle bundleWithPath:lprojPath];
        }

        sBundle = resBundle;
    });
    return sBundle;
}

#pragma mark - Command-Line Parsing

/* clangd behavior workarounds */
#define STRINGIFY(x) #x
#define EXPAND_AND_STRINGIFY(x) STRINGIFY(x)
#define MYSTRINGIFY(x)                                                                                                 \
    ^{                                                                                                                 \
        NSString *str = [NSString stringWithUTF8String:EXPAND_AND_STRINGIFY(x)];                                       \
        if ([str hasPrefix:@"\""])                                                                                     \
            str = [str substringFromIndex:1];                                                                          \
        if ([str hasSuffix:@"\""])                                                                                     \
            str = [str substringToIndex:str.length - 1];                                                               \
        return strdup([str UTF8String]);                                                                               \
    }()

static void printUsageAndExit(const char *prog) {
    // Compact, grouped usage for quick reference. See README for detailed explanations.
    static const char *sPackageScheme = MYSTRINGIFY(THEOS_PACKAGE_SCHEME);
    static const char *sPackageVersion = MYSTRINGIFY(PACKAGE_VERSION);

    fprintf(stderr, "TrollVNC (%s) v%s\n", sPackageScheme, sPackageVersion);
    fprintf(stderr, "Usage: %s [-p port] [-n name] [options]\n\n", prog);

    fprintf(stderr, "Basic:\n");
    fprintf(stderr, "  -b host    Bind host address (IPv4/IPv6 literal, default to all)\n");
    fprintf(stderr, "  -p port    VNC TCP port (default: %d)\n", gPort);
    fprintf(stderr, "  -c port    Client management TCP port (0=off, default: 0)\n");
    fprintf(stderr, "  -n name    Desktop name (default: %s)\n", [gDesktopName UTF8String]);
    fprintf(stderr, "  -v         View-only (ignore input)\n");
    fprintf(stderr, "  -A sec     Keep-alive interval to prevent sleep; only when clients > 0 (15..86400, 0=off)\n\n");

    fprintf(stderr, "Display/Perf:\n");
    fprintf(stderr, "  -s scale   Output scale 0<s<=1 (default: %.2f)\n", gScale);
    fprintf(stderr, "  -F spec    Frame rate: fps | min-max | min:pref:max\n");
    fprintf(stderr, "  -d sec     Defer window (0..0.5, default: %.3f)\n", gDeferWindowSec);
    fprintf(stderr, "  -Q n       Max in-flight encodes (0=never drop, default: %d)\n\n", gMaxInflightUpdates);

    fprintf(stderr, "Dirty detection:\n");
    fprintf(stderr, "  -t size    Tile size (8..128, default: %d)\n", gTileSize);
    fprintf(stderr, "  -P pct     Fullscreen fallback threshold (0..100; 0=disable dirty detection, default: %d)\n",
            gFullscreenThresholdPercent);
    fprintf(stderr, "  -R max     Max dirty rects before bbox (default: %d)\n", gMaxRectsLimit);
    fprintf(stderr, "  -a         Non-blocking swap (may cause tearing)\n\n");

    fprintf(stderr, "Scroll/Input:\n");
    fprintf(stderr, "  -W px      Wheel step in pixels (0=disable, default: %.0f)\n", gWheelStepPx);
    fprintf(stderr,
            "  -w k=v,.. Wheel tuning keys: step,coalesce,max,clamp,amp,cap,minratio,durbase,durk,durmin,durmax\n");
    fprintf(stderr, "  -N         Natural scroll direction (invert wheel)\n");
    fprintf(stderr, "  -M scheme  Modifier mapping: std|altcmd (default: std)\n");
    fprintf(stderr, "  -K         Log keyboard events to stderr\n\n");

    fprintf(stderr, "HTTP/WebSockets:\n");
    fprintf(stderr, "  -H port    Enable built-in HTTP server on port (0=off, default: 0)\n");
    fprintf(stderr, "  -D path    Absolute path for HTTP document root\n");
    fprintf(stderr, "  -e file    Path to SSL certificate file\n");
    fprintf(stderr, "  -k file    Path to SSL private key file\n\n");

    fprintf(stderr, "Bonjour/mDNS:\n");
    fprintf(stderr, "  -B on|off  Advertise on local network via Bonjour (_rfb._tcp, _http._tcp) (default: on)\n\n");

    fprintf(stderr, "Accessibility:\n");
    fprintf(stderr, "  -O on|off  Observe iOS interface orientation and sync (default: on)\n");
    fprintf(stderr, "  -E on|off  Enable AssistiveTouch auto-activation (default: off)\n");
    fprintf(stderr, "  -U on|off  Enable server-side cursor X (default: off)\n\n");

    fprintf(stderr, "Notifications:\n");
    fprintf(stderr, "  -i on|off  Single notification when first client connects (default: on)\n");
    fprintf(stderr, "  -I on|off  User notifications for client connect/disconnect (default: on)\n\n");

    fprintf(stderr, "Extensions:\n");
    fprintf(stderr, "  -C on|off  Clipboard sync (default: on)\n");
    fprintf(stderr, "  -T on|off  File transfer (default: off)\n\n");

#if DEBUG
    fprintf(stderr, "Logging:\n");
    fprintf(stderr, "  -V         Enable verbose logging\n\n");
#endif

    fprintf(stderr, "Help:\n");
    fprintf(stderr, "  -h         Show this help message\n\n");

    fprintf(stderr, "Reverse Connection:\n");
    fprintf(stderr, "  %s -reverse host:port [options]\n", prog);
    fprintf(stderr, "  %s -repeater id host:port [options]\n\n", prog);

    fprintf(stderr, "Environment:\n");
    fprintf(
        stderr,
        "  TROLLVNC_PASSWORD                 Classic VNC password (enables VNC auth when set; first 8 chars used)\n");
    fprintf(stderr,
            "  TROLLVNC_VIEWONLY_PASSWORD        View-only password; passwords stored as [full..., view-only...]\n");
    fprintf(stderr, "  TROLLVNC_REPEATER_RETRY_INTERVAL  Repeater retry interval (default: 0)\n\n");

    exit(EXIT_SUCCESS);
}

static void parseWheelOptions(const char *spec) {
    if (!spec)
        return;
    char *dup = strdup(spec);
    if (!dup)
        return;
    char *saveptr = NULL;
    for (char *tok = strtok_r(dup, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        char *eq = strchr(tok, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *key = tok;
        const char *val = eq + 1;
        double d = strtod(val, NULL);
        if (strcmp(key, "step") == 0) {
            if (d > 0)
                gWheelStepPx = d;
            TVLog(@"Wheel tuning: step=%g", gWheelStepPx);
        } else if (strcmp(key, "coalesce") == 0) {
            if (d >= 0 && d <= 0.5)
                gWheelCoalesceSec = d;
            TVLog(@"Wheel tuning: coalesce=%g", gWheelCoalesceSec);
        } else if (strcmp(key, "max") == 0) {
            if (d > 0)
                gWheelMaxStepPx = d;
            TVLog(@"Wheel tuning: max=%g", gWheelMaxStepPx);
        } else if (strcmp(key, "clamp") == 0) {
            if (d >= 1.0 && d <= 10.0)
                gWheelAbsClampFactor = d;
            TVLog(@"Wheel tuning: clamp=%g", gWheelAbsClampFactor);
        } else if (strcmp(key, "amp") == 0) {
            if (d >= 0.0 && d <= 5.0)
                gWheelAmpCoeff = d;
            TVLog(@"Wheel tuning: amp=%g", gWheelAmpCoeff);
        } else if (strcmp(key, "cap") == 0) {
            if (d >= 0.0 && d <= 2.0)
                gWheelAmpCap = d;
            TVLog(@"Wheel tuning: cap=%g", gWheelAmpCap);
        } else if (strcmp(key, "minratio") == 0) {
            if (d >= 0.0 && d <= 2.0)
                gWheelMinTakeRatio = d;
            TVLog(@"Wheel tuning: minratio=%g", gWheelMinTakeRatio);
        } else if (strcmp(key, "durbase") == 0) {
            if (d >= 0.0 && d <= 1.0)
                gWheelDurBase = d;
            TVLog(@"Wheel tuning: durbase=%g", gWheelDurBase);
        } else if (strcmp(key, "durk") == 0) {
            if (d >= 0.0 && d <= 1.0)
                gWheelDurK = d;
            TVLog(@"Wheel tuning: durk=%g", gWheelDurK);
        } else if (strcmp(key, "durmin") == 0) {
            if (d >= 0.0 && d <= 1.0)
                gWheelDurMin = d;
            TVLog(@"Wheel tuning: durmin=%g", gWheelDurMin);
        } else if (strcmp(key, "durmax") == 0) {
            if (d >= 0.0 && d <= 2.0)
                gWheelDurMax = d;
            TVLog(@"Wheel tuning: durmax=%g", gWheelDurMax);
        } else if (strcmp(key, "natural") == 0) {
            gWheelNaturalDir = (d != 0.0);
            TVLog(@"Wheel tuning: natural=%@", gWheelNaturalDir ? @"YES" : @"NO");
        }
    }
    free(dup);
}

static void parseDaemonOptions(void) {
    NSDictionary *prefs = nil;

    if (!prefs) {
        NSBundle *resBundle = tvResourceBundle();
        NSString *presetPath = [resBundle pathForResource:@"Managed" ofType:@"plist"];
        if (presetPath) {
            prefs = [NSDictionary dictionaryWithContentsOfFile:presetPath];
        }
    }

    if (!prefs) {
        prefs = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.82flex.trollvnc"];
    }

    if (!prefs) {
        TVLog(@"-daemon: no preferences found for domain com.82flex.trollvnc");
        return;
    }

    // Strings
    NSString *desktopName = [prefs objectForKey:@"DesktopName"];
    if ([desktopName isKindOfClass:[NSString class]] && desktopName.length > 0) {
        gDesktopName = desktopName;
    } else if (desktopName) {
        TVLog(@"-daemon: DesktopName is empty; using default '%@'", gDesktopName);
    }

    NSString *bindHost = [prefs objectForKey:@"BindHost"];
    if ([bindHost isKindOfClass:[NSString class]]) {
        if (bindHost.length > 0) {
            gBindHost = bindHost;
            TVLog(@"-daemon: BindHost=%@", gBindHost);
        } else {
            gBindHost = nil;
            TVLog(@"-daemon: BindHost empty; cleared to default (any)");
        }
    }

    // Numbers
    NSNumber *portN = [prefs objectForKey:@"Port"];
    if ([portN isKindOfClass:[NSNumber class]] || [portN isKindOfClass:[NSString class]]) {
        int v = portN.intValue;
        if (v < 1024 || v > 65535) {
            // Privileged or invalid -> fallback to default 5901
            TVLog(@"-daemon: invalid TCP Port=%d; using default 5901", v);
            gPort = 5901;
        } else {
            gPort = v;
        }
    }

    NSNumber *keepAliveN = [prefs objectForKey:@"KeepAliveSec"];
    if ([keepAliveN isKindOfClass:[NSNumber class]]) {
        double v = keepAliveN.doubleValue;
        if (v < 0.0) {
            TVLog(@"-daemon: KeepAliveSec < 0; set to 0");
            v = 0.0;
        } else if (v > 0.0 && v < 15.0) {
            TVLog(@"-daemon: KeepAliveSec < 15; treated as 0 (off)");
            v = 0.0;
        } else if (v > 300.0) {
            TVLog(@"-daemon: KeepAliveSec > 300; clamped to 300");
            v = 300.0;
        }
        gKeepAliveSec = v;
    }

    NSNumber *scaleN = [prefs objectForKey:@"Scale"];
    if ([scaleN isKindOfClass:[NSNumber class]]) {
        double v = scaleN.doubleValue;
        if (v <= 0.0 || v > 1.0) {
            TVLog(@"-daemon: invalid Scale=%.3f; clamped to [0.1..1.0]", v);
        }
        if (v < 0.1)
            v = 0.1;
        if (v > 1.0)
            v = 1.0;
        gScale = v;
    }

    NSNumber *deferN = [prefs objectForKey:@"DeferWindowSec"];
    if ([deferN isKindOfClass:[NSNumber class]]) {
        double v = deferN.doubleValue;
        if (v < 0.0) {
            TVLog(@"-daemon: DeferWindowSec < 0; set to 0");
            v = 0.0;
        }
        if (v > 0.5) {
            TVLog(@"-daemon: DeferWindowSec > 0.5; clamped to 0.5");
            v = 0.5;
        }
        gDeferWindowSec = v;
    }

    NSNumber *maxInflightN = [prefs objectForKey:@"MaxInflight"];
    if ([maxInflightN isKindOfClass:[NSNumber class]]) {
        int v = maxInflightN.intValue;
        if (v < 0) {
            TVLog(@"-daemon: MaxInflight < 0; set to 0");
            v = 0;
        }
        if (v > 8) {
            TVLog(@"-daemon: MaxInflight > 8; clamped to 8");
            v = 8;
        }
        gMaxInflightUpdates = v;
    }

    NSNumber *tileSizeN = [prefs objectForKey:@"TileSize"];
    if ([tileSizeN isKindOfClass:[NSNumber class]]) {
        int v = tileSizeN.intValue;
        if (v < 8) {
            TVLog(@"-daemon: TileSize < 8; set to 8");
            v = 8;
        }
        if (v > 128) {
            TVLog(@"-daemon: TileSize > 128; clamped to 128");
            v = 128;
        }
        gTileSize = v;
    }

    NSNumber *fullThreshN = [prefs objectForKey:@"FullscreenThresholdPercent"];
    if ([fullThreshN isKindOfClass:[NSNumber class]]) {
        int v = fullThreshN.intValue;
        if (v < 0) {
            TVLog(@"-daemon: FullscreenThresholdPercent < 0; set to 0");
            v = 0;
        }
        if (v > 100) {
            TVLog(@"-daemon: FullscreenThresholdPercent > 100; clamped to 100");
            v = 100;
        }
        gFullscreenThresholdPercent = v;
    }

    NSNumber *maxRectsN = [prefs objectForKey:@"MaxRects"];
    if ([maxRectsN isKindOfClass:[NSNumber class]]) {
        int v = maxRectsN.intValue;
        if (v < 1) {
            TVLog(@"-daemon: MaxRects < 1; set to 1");
            v = 1;
        }
        if (v > 4096) {
            TVLog(@"-daemon: MaxRects > 4096; clamped to 4096");
            v = 4096;
        }
        gMaxRectsLimit = v;
    }

    NSNumber *wheelPxN = [prefs objectForKey:@"WheelStepPx"];
    if ([wheelPxN isKindOfClass:[NSNumber class]]) {
        double v = wheelPxN.doubleValue;
        if (v == 0.0) {
            gWheelStepPx = 0.0;
            gWheelMaxStepPx = 0.0;
            TVLog(@"-daemon: Wheel emulation disabled (step=0)");
        } else {
            if (v <= 4.0) {
                TVLog(@"-daemon: WheelStepPx <= 4; raised to 5");
                v = 5.0;
            }
            if (v > 1000.0) {
                TVLog(@"-daemon: WheelStepPx > 1000; clamped to 1000");
                v = 1000.0;
            }
            gWheelStepPx = v;
            gWheelMaxStepPx = fmax(2.0 * gWheelStepPx, 96.0) * 1.0;
        }
    }

    NSNumber *httpPortN = [prefs objectForKey:@"HttpPort"];
    if ([httpPortN isKindOfClass:[NSNumber class]] || [httpPortN isKindOfClass:[NSString class]]) {
        int v = httpPortN.intValue;
        if (v == 0) {
            gHttpPort = 0; // disabled
        } else if (v < 0 || v > 65535 || v < 1024) {
            TVLog(@"-daemon: invalid HTTP Port=%d; using default 0 (disabled)", v);
            gHttpPort = 0;
        } else {
            gHttpPort = v;
        }
    }

    // Booleans
    NSNumber *enableN = [prefs objectForKey:@"Enabled"];
    if ([enableN isKindOfClass:[NSNumber class]])
        gEnabled = enableN.boolValue;
    NSNumber *clipN = [prefs objectForKey:@"ClipboardEnabled"];
    if ([clipN isKindOfClass:[NSNumber class]])
        gClipboardEnabled = clipN.boolValue;
    NSNumber *viewOnlyN = [prefs objectForKey:@"ViewOnly"];
    if ([viewOnlyN isKindOfClass:[NSNumber class]])
        gViewOnly = viewOnlyN.boolValue;
    NSNumber *orientN = [prefs objectForKey:@"OrientationSync"];
    if ([orientN isKindOfClass:[NSNumber class]])
        gOrientationSyncEnabled = orientN.boolValue;
    NSNumber *orientFixN = [prefs objectForKey:@"OrientationPadFix"];
    if ([orientFixN isKindOfClass:[NSNumber class]])
        gShouldApplyOrientationFix = orientFixN.boolValue;
    NSNumber *naturalN = [prefs objectForKey:@"NaturalScroll"];
    if ([naturalN isKindOfClass:[NSNumber class]])
        gWheelNaturalDir = naturalN.boolValue;
    NSNumber *cursorN = [prefs objectForKey:@"ServerCursor"];
    if ([cursorN isKindOfClass:[NSNumber class]])
        gCursorEnabled = cursorN.boolValue;
    NSNumber *asyncSwapN = [prefs objectForKey:@"AsyncSwap"];
    if ([asyncSwapN isKindOfClass:[NSNumber class]])
        gAsyncSwapEnabled = asyncSwapN.boolValue;
    NSNumber *keyLogN = [prefs objectForKey:@"KeyLogging"];
    if ([keyLogN isKindOfClass:[NSNumber class]])
        gKeyEventLogging = keyLogN.boolValue;
    NSNumber *assistN = [prefs objectForKey:@"AutoAssistEnabled"];
    if ([assistN isKindOfClass:[NSNumber class]])
        gAutoAssistEnabled = assistN.boolValue;
    NSNumber *bonjourN = [prefs objectForKey:@"BonjourEnabled"];
    if ([bonjourN isKindOfClass:[NSNumber class]])
        gBonjourEnabled = bonjourN.boolValue;
    NSNumber *fileN = [prefs objectForKey:@"FileTransferEnabled"];
    if ([fileN isKindOfClass:[NSNumber class]])
        gFileTransferEnabled = fileN.boolValue;
    NSNumber *singleNotifN = [prefs objectForKey:@"SingleNotifEnabled"];
    if ([singleNotifN isKindOfClass:[NSNumber class]])
        gUserSingleNotifsEnabled = singleNotifN.boolValue;
    NSNumber *clientNotifsN = [prefs objectForKey:@"ClientNotifsEnabled"];
    if ([clientNotifsN isKindOfClass:[NSNumber class]])
        gUserClientNotifsEnabled = clientNotifsN.boolValue;

    // Modifier mapping
    NSString *modMap = [prefs objectForKey:@"ModifierMap"];
    if ([modMap isKindOfClass:[NSString class]]) {
        if ([modMap isEqualToString:@"altcmd"])
            gModMapScheme = 1;
        else
            gModMapScheme = 0;
    }

    // Frame rate spec (validate and normalize)
    NSString *fpsSpec = [prefs objectForKey:@"FrameRateSpec"];
    if ([fpsSpec isKindOfClass:[NSString class]] && fpsSpec.length > 0) {
        const char *spec = fpsSpec.UTF8String ?: "";
        int minV = 0, prefV = 0, maxV = 0;
        const char *colon1 = strchr(spec, ':');
        const char *dash = strchr(spec, '-');
        if (colon1) {
            long a = strtol(spec, NULL, 10);
            const char *p2 = colon1 + 1;
            const char *colon2 = strchr(p2, ':');
            if (colon2) {
                long b = strtol(p2, NULL, 10);
                long c = strtol(colon2 + 1, NULL, 10);
                minV = (int)a;
                prefV = (int)b;
                maxV = (int)c;
            }
        } else if (dash) {
            long a = strtol(spec, NULL, 10);
            long b = strtol(dash + 1, NULL, 10);
            minV = (int)a;
            prefV = (int)b;
            maxV = (int)b;
        } else {
            long v = strtol(spec, NULL, 10);
            minV = (int)v;
            prefV = (int)v;
            maxV = (int)v;
        }
        // Normalize & validate: allow 0..240 (0 = unspecified)
        if (minV < 0)
            minV = 0;
        if (minV > 240)
            minV = 240;
        if (prefV < 0)
            prefV = 0;
        if (prefV > 240)
            prefV = 240;
        if (maxV < 0)
            maxV = 0;
        if (maxV > 240)
            maxV = 240;
        if (minV > 0 && maxV > 0 && minV > maxV) {
            int tmp = minV;
            minV = maxV;
            maxV = tmp;
        }
        if (prefV > 0) {
            if (minV > 0 && prefV < minV)
                prefV = minV;
            if (maxV > 0 && prefV > maxV)
                prefV = maxV;
        }
        gFpsMin = minV;
        gFpsPref = prefV;
        gFpsMax = maxV;
    }

    // Wheel tuning (advanced)
    NSString *wheelTuning = [prefs objectForKey:@"WheelTuning"];
    if ([wheelTuning isKindOfClass:[NSString class]] && wheelTuning.length > 0) {
        parseWheelOptions(wheelTuning.UTF8String);
    }

    // HTTP dir override and SSL (require absolute paths)
    NSString *httpDir = [prefs objectForKey:@"HttpDir"];
    if ([httpDir isKindOfClass:[NSString class]] && httpDir.length > 0) {
        if (![httpDir hasPrefix:@"/"]) {
            TVLog(@"-daemon: HttpDir must be absolute: %@ (ignored)", httpDir);
        } else {
            gHttpDirOverride = strdup(httpDir.fileSystemRepresentation);
        }
    }
    NSString *sslCert = [prefs objectForKey:@"SslCertFile"];
    if ([sslCert isKindOfClass:[NSString class]] && sslCert.length > 0) {
        if (![sslCert hasPrefix:@"/"]) {
            TVLog(@"-daemon: SslCertFile must be absolute: %@ (ignored)", sslCert);
        } else {
            gSslCertPath = strdup(sslCert.fileSystemRepresentation);
        }
    }
    NSString *sslKey = [prefs objectForKey:@"SslKeyFile"];
    if ([sslKey isKindOfClass:[NSString class]] && sslKey.length > 0) {
        if (![sslKey hasPrefix:@"/"]) {
            TVLog(@"-daemon: SslKeyFile must be absolute: %@ (ignored)", sslKey);
        } else {
            gSslKeyPath = strdup(sslKey.fileSystemRepresentation);
        }
    }

    // Reverse Connection (26.1) from preferences
    // Expected keys (per Root.plist):
    //  - ReverseMode: "viewer" (default) | "repeater"
    //  - ReverseSocket: "host:port" or "[ipv6]:port"
    //  - ReverseRepeaterID: number id (only used when mode=repeater)
    NSString *revMode = [prefs objectForKey:@"ReverseMode"];
    if ([revMode isKindOfClass:[NSString class]]) {
        if ([revMode caseInsensitiveCompare:@"repeater"] == NSOrderedSame) {
            gRepeaterMode = 2;
        } else if ([revMode caseInsensitiveCompare:@"viewer"] == NSOrderedSame) {
            gRepeaterMode = 1;
        } else {
            gRepeaterMode = 0;
        }
    }
    NSString *revSock = [prefs objectForKey:@"ReverseSocket"];
    if ([revSock isKindOfClass:[NSString class]] && revSock.length > 0) {
        const char *hp = revSock.UTF8String;
        const char *hostBegin = hp;
        const char *hostEnd = NULL;
        const char *portStr = NULL;
        if (hp[0] == '[') {
            const char *rb = strchr(hp, ']');
            if (rb && rb[1] == ':') {
                hostBegin = hp + 1;
                hostEnd = rb;
                portStr = rb + 2;
            }
        } else {
            const char *colon = strrchr(hp, ':');
            if (colon && colon != hp && *(colon + 1) != '\0') {
                hostBegin = hp;
                hostEnd = colon;
                portStr = colon + 1;
            }
        }
        if (hostEnd && portStr) {
            long pv = strtol(portStr, NULL, 10);
            if (pv > 0 && pv <= 65535) {
                size_t hostLen = (size_t)(hostEnd - hostBegin);
                if (hostLen > 0) {
                    char *hostDup = (char *)malloc(hostLen + 1);
                    if (hostDup) {
                        memcpy(hostDup, hostBegin, hostLen);
                        hostDup[hostLen] = '\0';
                        if (gRepeaterHost) {
                            free(gRepeaterHost);
                            gRepeaterHost = NULL;
                        }
                        gRepeaterHost = hostDup;
                        gRepeaterPort = (int)pv;
                    }
                }
            } else {
                TVLog(@"-daemon: ReverseSocket port invalid: %ld (ignored)", pv);
            }
        } else {
            TVLog(@"-daemon: ReverseSocket invalid: %@ (expected host:port or [ipv6]:port)", revSock);
        }
    } else {
        // Backward-compat: accept separate ReverseHost/ReversePort if present
        NSString *revHost = [prefs objectForKey:@"ReverseHost"];
        if ([revHost isKindOfClass:[NSString class]] && revHost.length > 0) {
            gRepeaterHost = strdup(revHost.UTF8String);
        }
        NSNumber *revPortN = [prefs objectForKey:@"ReversePort"];
        if ([revPortN isKindOfClass:[NSNumber class]] || [revPortN isKindOfClass:[NSString class]]) {
            int v = revPortN.intValue;
            if (v > 0 && v <= 65535) {
                gRepeaterPort = v;
            }
        }
    }
    NSNumber *revIdN = [prefs objectForKey:@"ReverseRepeaterID"];
    if ([revIdN isKindOfClass:[NSNumber class]] || [revIdN isKindOfClass:[NSString class]]) {
        gRepeaterId = revIdN.intValue;
    }

    // If reverse connection is configured, override mutually exclusive options here in daemon mode
    if (isRepeaterEnabled()) {
        gPort = -1;    // disable local listening
        gHttpPort = 0; // disable HTTP server
        if (gHttpDirOverride) {
            free(gHttpDirOverride);
            gHttpDirOverride = NULL;
        }
        gBonjourEnabled = NO; // disable Bonjour advertisement
        TVLog(@"-daemon: Reverse enabled -> overriding: port=-1, http=0, bonjour=off");
    }

    // Passwords via environment (leveraging existing setupRfbClassicAuthentication).
    // Classic VNC authentication uses only first 8 chars; truncate here for clarity.
    NSString *fullPwd = [prefs objectForKey:@"FullPassword"];
    BOOL hasFullPwd = NO, hasViewPwd = NO;
    if ([fullPwd isKindOfClass:[NSString class]]) {
        NSString *trunc = (fullPwd.length > 8) ? [fullPwd substringToIndex:8] : fullPwd;
        setenv("TROLLVNC_PASSWORD", trunc.UTF8String ?: "", 1);
        hasFullPwd = (trunc.length > 0);
    }
    NSString *viewPwd = [prefs objectForKey:@"ViewOnlyPassword"];
    if ([viewPwd isKindOfClass:[NSString class]]) {
        NSString *trunc = (viewPwd.length > 8) ? [viewPwd substringToIndex:8] : viewPwd;
        setenv("TROLLVNC_VIEWONLY_PASSWORD", trunc.UTF8String ?: "", 1);
        hasViewPwd = (trunc.length > 0);
    }

    // Single-line summary using NSMutableString; include reverse-connection fields and new options
    NSMutableString *cfg = [NSMutableString stringWithFormat:@"-daemon: cfg "];
    [cfg appendFormat:@"name='%@' ", gDesktopName];
    [cfg appendFormat:@"bindHost='%@' ", gBindHost];
    [cfg appendFormat:@"port=%d http=%d ", gPort, gHttpPort];

    // Reverse connection summary
    const char *revModeStr = isRepeaterEnabled() ? (gRepeaterMode == 2 ? "repeater" : "viewer") : "off";
    NSString *revHostStr = gRepeaterHost ? [NSString stringWithUTF8String:gRepeaterHost] : nil;
    [cfg appendFormat:@"reverse=%s host=%@ port=%d id=%d ", revModeStr, revHostStr, gRepeaterPort, gRepeaterId];

    // Core feature flags
    [cfg appendFormat:@"viewOnly=%@ clip=%@ keepAlive=%.0fs ", gViewOnly ? @"YES" : @"NO",
                      gClipboardEnabled ? @"YES" : @"NO", gKeepAliveSec];
    [cfg appendFormat:@"scale=%.2f fps=%d:%d:%d defer=%.3f ", gScale, gFpsMin, gFpsPref, gFpsMax, gDeferWindowSec];
    [cfg appendFormat:@"inflight=%d tile=%d full%%=%d rects=%d ", gMaxInflightUpdates, gTileSize,
                      gFullscreenThresholdPercent, gMaxRectsLimit];
    [cfg appendFormat:@"async=%@ cursor=%@ orient=%@ orientFix=%@ keylog=%@ ", gAsyncSwapEnabled ? @"YES" : @"NO",
                      gCursorEnabled ? @"YES" : @"NO", gOrientationSyncEnabled ? @"YES" : @"NO",
                      gShouldApplyOrientationFix ? @"YES" : @"NO", gKeyEventLogging ? @"YES" : @"NO"];

    // Wheel / input tuning
    [cfg appendFormat:@"wheel=%.1f natural=%@ mod=%s ", gWheelStepPx, gWheelNaturalDir ? @"YES" : @"NO",
                      (gModMapScheme == 1) ? "altcmd" : "std"];

    // Networking / discovery
    [cfg appendFormat:@"bonjour=%@ ", gBonjourEnabled ? @"on" : @"off"];
    [cfg appendFormat:@"fileXfer=%@ ", gFileTransferEnabled ? @"on" : @"off"];

    // Auth and paths
    [cfg appendFormat:@"auth(full=%@,view=%@,8char) ", hasFullPwd ? @"on" : @"off", hasViewPwd ? @"on" : @"off"];
    NSString *dirStr = gHttpDirOverride ? [NSString stringWithUTF8String:gHttpDirOverride] : nil;
    NSString *certStr = gSslCertPath ? [NSString stringWithUTF8String:gSslCertPath] : nil;
    NSString *keyStr = gSslKeyPath ? [NSString stringWithUTF8String:gSslKeyPath] : nil;
    [cfg appendFormat:@"dir=%@ cert=%@ key=%@", dirStr, certStr, keyStr];

    TVLog(@"%@", cfg);
    TVLog(@"-daemon: preferences applied (domain=com.82flex.trollvnc)");
}

static void parseCLI(int argc, const char *argv[]) {
    // Special mode: -daemon reads configuration from NSUserDefaults domain
    // com.82flex.trollvnc and initializes runtime options accordingly.
    BOOL isDaemon = NO;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-daemon") == 0) {
            isDaemon = YES;
            break;
        }
    }
    if (isDaemon) {
        gIsDaemonMode = YES;
        gTvCtlPort = kTvDefaultCtlPort;
        parseDaemonOptions();
        return;
    }

    // Pre-scan for Reverse Connection long options (-reverse, -repeater)
    // Build a filtered argv without these options for getopt handling of the rest.
    std::vector<const char *> __filtered;
    __filtered.reserve((size_t)argc);
    __filtered.push_back(argv[0]);

    BOOL __reverseEnabled = NO;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "-reverse") == 0) {
            if (i + 1 >= argc) {
                TVPrintError("-reverse requires host:port");
                exit(EXIT_FAILURE);
            }

            const char *hp = argv[++i];
            const char *hostBegin = hp;
            const char *hostEnd = NULL;
            const char *portStr = NULL;

            if (hp[0] == '[') {
                const char *rb = strchr(hp, ']');
                if (!rb || rb[1] != ':') {
                    TVPrintError("Invalid -reverse target: %s (expected [host]:port)", hp);
                    exit(EXIT_FAILURE);
                }

                hostBegin = hp + 1;
                hostEnd = rb;
                portStr = rb + 2;
            } else {
                const char *colon = strrchr(hp, ':');
                if (!colon || colon == hp || *(colon + 1) == '\0') {
                    TVPrintError("Invalid -reverse target: %s (expected host:port)", hp);
                    exit(EXIT_FAILURE);
                }

                hostBegin = hp;
                hostEnd = colon;
                portStr = colon + 1;
            }

            int port = (int)strtol(portStr, NULL, 10);
            if (port <= 0 || port > 65535) {
                TVPrintError("Invalid -reverse port: %s", portStr);
                exit(EXIT_FAILURE);
            }

            size_t hostLen = (size_t)(hostEnd - hostBegin);
            if (hostLen == 0) {
                TVPrintError("Invalid -reverse host (empty)");
                exit(EXIT_FAILURE);
            }

            char *hostDup = (char *)malloc(hostLen + 1);
            if (!hostDup) {
                TVPrintError("Out of memory");
                exit(EXIT_FAILURE);
            }

            memcpy(hostDup, hostBegin, hostLen);
            hostDup[hostLen] = '\0';

            if (gRepeaterHost) {
                free(gRepeaterHost);
                gRepeaterHost = NULL;
            }

            gRepeaterMode = 1;
            gRepeaterHost = hostDup;
            gRepeaterPort = port;

            TVLog(@"CLI: Reverse connection to %@:%d", [NSString stringWithUTF8String:gRepeaterHost], gRepeaterPort);

            __reverseEnabled = YES;
            continue; // skip adding this arg
        }
        if (strcmp(arg, "-repeater") == 0) {
            if (i + 2 >= argc) {
                TVPrintError("-repeater requires: id host:port");
                exit(EXIT_FAILURE);
            }

            const char *idStr = argv[++i];
            long repId = strtol(idStr, NULL, 10);
            if (repId < 0 || repId > INT_MAX) {
                TVPrintError("Invalid repeater id: %s", idStr);
                exit(EXIT_FAILURE);
            }

            const char *hp = argv[++i];
            const char *hostBegin = hp;
            const char *hostEnd = NULL;
            const char *portStr = NULL;

            if (hp[0] == '[') {
                const char *rb = strchr(hp, ']');
                if (!rb || rb[1] != ':') {
                    TVPrintError("Invalid -repeater target: %s (expected [host]:port)", hp);
                    exit(EXIT_FAILURE);
                }

                hostBegin = hp + 1;
                hostEnd = rb;
                portStr = rb + 2;
            } else {
                const char *colon = strrchr(hp, ':');
                if (!colon || colon == hp || *(colon + 1) == '\0') {
                    TVPrintError("Invalid -repeater target: %s (expected host:port)", hp);
                    exit(EXIT_FAILURE);
                }

                hostBegin = hp;
                hostEnd = colon;
                portStr = colon + 1;
            }

            int port = (int)strtol(portStr, NULL, 10);
            if (port <= 0 || port > 65535) {
                TVPrintError("Invalid -repeater port: %s", portStr);
                exit(EXIT_FAILURE);
            }

            size_t hostLen = (size_t)(hostEnd - hostBegin);
            if (hostLen == 0) {
                TVPrintError("Invalid -repeater host (empty)");
                exit(EXIT_FAILURE);
            }

            char *hostDup = (char *)malloc(hostLen + 1);
            if (!hostDup) {
                TVPrintError("Out of memory");
                exit(EXIT_FAILURE);
            }

            memcpy(hostDup, hostBegin, hostLen);
            hostDup[hostLen] = '\0';

            if (gRepeaterHost) {
                free(gRepeaterHost);
                gRepeaterHost = NULL;
            }

            gRepeaterMode = 2;
            gRepeaterId = (int)repId;
            gRepeaterHost = hostDup;
            gRepeaterPort = port;

            TVLog(@"CLI: Repeater mode id=%d target=%@:%d", gRepeaterId, [NSString stringWithUTF8String:gRepeaterHost],
                  gRepeaterPort);

            __reverseEnabled = YES;
            continue; // skip adding this arg
        }

        __filtered.push_back(arg);
    }

    // Prepare argv for getopt from filtered vector
    int __argc2 = (int)__filtered.size();
    std::vector<char *> __argv2;
    __argv2.reserve(__filtered.size());
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++11-extensions"
    for (const char *s : __filtered)
        __argv2.push_back(const_cast<char *>(s));
#pragma clang diagnostic pop

    int opt;
    const char *optstr = "p:b:n:vA:c:C:s:F:d:Q:t:P:R:aW:w:NM:KU:O:o:I:i:H:D:e:k:B:T:Vh";
    optind = 1;
    while ((opt = getopt(__argc2, __argv2.data(), optstr)) != -1) {
        switch (opt) {
        case 'b': {
            if (!optarg || !*optarg) {
                TVPrintError("-b requires a non-empty host name or address");
                exit(EXIT_FAILURE);
            }
            gBindHost = [NSString stringWithUTF8String:optarg];
            TVLog(@"CLI: Bind host set to '%@'", gBindHost);
            break;
        }
        case 'p': {
            long port = strtol(optarg, NULL, 10);
            if (port <= 0 || port > 65535) {
                TVPrintError("Invalid port: %s", optarg);
                exit(EXIT_FAILURE);
            }
            gPort = (int)port;
            TVLog(@"CLI: Port set to %d", gPort);
            break;
        }
        case 'n': {
            gDesktopName = [NSString stringWithUTF8String:optarg ?: "TrollVNC"];
            TVLog(@"CLI: Desktop name set to '%@'", gDesktopName);
            break;
        }
        case 'v': {
            gViewOnly = YES;
            TVLog(@"CLI: View-only mode enabled (-v)");
            break;
        }
        case 'A': {
            double sec = strtod(optarg ? optarg : "0", NULL);
            if (sec < 15.0 || sec > 24 * 3600.0) {
                TVPrintError("Invalid keep-alive seconds: %s (expected 15..86400)", optarg);
                exit(EXIT_FAILURE);
            }
            gKeepAliveSec = sec;
            TVLog(@"CLI: KeepAlive interval set to %.3f sec (-A)", gKeepAliveSec);
            break;
        }
        case 'c': {
            long port = strtol(optarg, NULL, 10);
            if (port <= 0 || port > 65535) {
                TVPrintError("Invalid port: %s", optarg);
                exit(EXIT_FAILURE);
            }
            gTvCtlPort = (int)port;
            TVLog(@"CLI: Mgmt port set to %d", gTvCtlPort);
            break;
        }
        case 'C': {
            const char *val = optarg ? optarg : "on";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gClipboardEnabled = YES;
                TVLog(@"CLI: Clipboard sync enabled (-C %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gClipboardEnabled = NO;
                TVLog(@"CLI: Clipboard sync disabled (-C %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -C value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 's': {
            double sc = strtod(optarg, NULL);
            if (!(sc > 0.0 && sc <= 1.0)) {
                TVPrintError("Invalid scale: %s (expected 0 < s <= 1)", optarg);
                exit(EXIT_FAILURE);
            }
            gScale = sc;
            TVLog(@"CLI: Output scale factor set to %.3f", gScale);
            break;
        }
        case 'F': {
            // Accept formats: "fps", "min-max", "min:pref:max"
            const char *spec = optarg ? optarg : "";
            int minV = 0, prefV = 0, maxV = 0;
            if (spec[0] == '\0') {
                break; // ignore empty
            }
            const char *colon1 = strchr(spec, ':');
            const char *dash = strchr(spec, '-');
            if (colon1) {
                // min:pref:max
                long a = strtol(spec, NULL, 10);
                const char *p2 = colon1 + 1;
                const char *colon2 = strchr(p2, ':');
                if (!colon2) {
                    TVPrintError("Invalid -F spec: %s (expected min:pref:max)", spec);
                    exit(EXIT_FAILURE);
                }
                long b = strtol(p2, NULL, 10);
                long c = strtol(colon2 + 1, NULL, 10);
                minV = (int)a;
                prefV = (int)b;
                maxV = (int)c;
            } else if (dash) {
                // min-max (preferred defaults to max)
                long a = strtol(spec, NULL, 10);
                long b = strtol(dash + 1, NULL, 10);
                minV = (int)a;
                prefV = (int)b;
                maxV = (int)b;
            } else {
                // single fps
                long v = strtol(spec, NULL, 10);
                minV = (int)v;
                prefV = (int)v;
                maxV = (int)v;
            }
            // Normalize & validate: allow 0..240 (0 = unspecified)
            if (minV < 0)
                minV = 0;
            if (minV > 240)
                minV = 240;
            if (prefV < 0)
                prefV = 0;
            if (prefV > 240)
                prefV = 240;
            if (maxV < 0)
                maxV = 0;
            if (maxV > 240)
                maxV = 240;
            if (minV > 0 && maxV > 0 && minV > maxV) {
                int tmp = minV;
                minV = maxV;
                maxV = tmp;
            }
            if (prefV > 0) {
                if (minV > 0 && prefV < minV)
                    prefV = minV;
                if (maxV > 0 && prefV > maxV)
                    prefV = maxV;
            }
            gFpsMin = minV;
            gFpsPref = prefV;
            gFpsMax = maxV;
            TVLog(@"CLI: FPS preference set to min=%d pref=%d max=%d", gFpsMin, gFpsPref, gFpsMax);
            break;
        }
        case 'd': {
            double s = strtod(optarg, NULL);
            if (s < 0.0 || s > 0.5) {
                TVPrintError("Invalid defer window seconds: %s (expected 0..0.5)", optarg);
                exit(EXIT_FAILURE);
            }
            gDeferWindowSec = s;
            TVLog(@"CLI: Defer window set to %.3f sec", gDeferWindowSec);
            break;
        }
        case 'Q': {
            long q = strtol(optarg, NULL, 10);
            if (q < 0 || q > 8) {
                TVPrintError("Invalid max in-flight: %s (expected 0..8)", optarg);
                exit(EXIT_FAILURE);
            }
            gMaxInflightUpdates = (int)q;
            TVLog(@"CLI: Max in-flight updates set to %d", gMaxInflightUpdates);
            break;
        }
        case 't': {
            long ts = strtol(optarg, NULL, 10);
            if (ts < 8 || ts > 128) {
                TVPrintError("Invalid tile size: %s (expected 8..128)", optarg);
                exit(EXIT_FAILURE);
            }
            gTileSize = (int)ts;
            TVLog(@"CLI: Tile size set to %d", gTileSize);
            break;
        }
        case 'P': {
            long p = strtol(optarg, NULL, 10);
            if (p < 0 || p > 100) {
                TVPrintError("Invalid threshold percent: %s (expected 0..100; 0 disables dirty detection)", optarg);
                exit(EXIT_FAILURE);
            }
            gFullscreenThresholdPercent = (int)p;
            TVLog(@"CLI: Fullscreen threshold percent set to %d", gFullscreenThresholdPercent);
            break;
        }
        case 'R': {
            long m = strtol(optarg, NULL, 10);
            if (m < 1 || m > 4096) {
                TVPrintError("Invalid max rects: %s (expected 1..4096)", optarg);
                exit(EXIT_FAILURE);
            }
            gMaxRectsLimit = (int)m;
            TVLog(@"CLI: Max rects limit set to %d", gMaxRectsLimit);
            break;
        }
        case 'a': {
            gAsyncSwapEnabled = YES;
            TVLog(@"CLI: Non-blocking swap enabled (-a)");
            break;
        }
        case 'W': {
            double px = strtod(optarg, NULL);
            if (px == 0.0) {
                // 0 disables wheel emulation
                gWheelStepPx = 0.0;
                gWheelMaxStepPx = 0.0;
                TVLog(@"CLI: Wheel emulation disabled (-W 0)");
                break;
            }
            if (!(px > 4.0 && px <= 1000.0)) {
                TVPrintError("Invalid wheel step px: %s (expected 0 or >4..<=1000)", optarg);
                exit(EXIT_FAILURE);
            }
            gWheelStepPx = px;
            // Scale max step roughly 4x and adjust duration slope mildly
            gWheelMaxStepPx = fmax(2.0 * gWheelStepPx, 96.0) * 1.0;
            TVLog(@"CLI: Wheel step set to %.1f px (max=%.1f)", gWheelStepPx, gWheelMaxStepPx);
            break;
        }
        case 'w': {
            parseWheelOptions(optarg);
            break;
        }
        case 'N': {
            gWheelNaturalDir = YES;
            TVLog(@"CLI: Natural scroll direction enabled (-N)");
            break;
        }
        case 'M': {
            const char *val = optarg ? optarg : "std";
            if (strcmp(val, "std") == 0)
                gModMapScheme = 0;
            else if (strcmp(val, "altcmd") == 0)
                gModMapScheme = 1;
            else {
                TVPrintError("Invalid -M scheme: %s (expected std|altcmd)", val);
                exit(EXIT_FAILURE);
            }
            TVLog(@"CLI: Modifier mapping set to %s", gModMapScheme == 0 ? "std" : "altcmd");
            break;
        }
        case 'K': {
            gKeyEventLogging = YES;
            TVLog(@"CLI: Keyboard event logging enabled (-K)");
            break;
        }
        case 'E': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gAutoAssistEnabled = YES;
                TVLog(@"CLI: AssistiveTouch auto-activation enabled (-E %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gAutoAssistEnabled = NO;
                TVLog(@"CLI: AssistiveTouch auto-activation disabled (-E %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -E value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'U': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gCursorEnabled = YES;
                TVLog(@"CLI: Cursor enabled (-U %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gCursorEnabled = NO;
                TVLog(@"CLI: Cursor disabled (-U %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -U value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'O': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gOrientationSyncEnabled = YES;
                TVLog(@"CLI: Orientation observer enabled (-O %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gOrientationSyncEnabled = NO;
                TVLog(@"CLI: Orientation observer disabled (-O %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -O value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'o': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gShouldApplyOrientationFix = YES;
                TVLog(@"CLI: Orientation fix enabled (-o %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gShouldApplyOrientationFix = NO;
                TVLog(@"CLI: Orientation fix disabled (-o %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -o value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'I': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gUserClientNotifsEnabled = YES;
                TVLog(@"CLI: Client user notifications enabled (-I %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gUserClientNotifsEnabled = NO;
                TVLog(@"CLI: Client user notifications disabled (-I %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -I value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'i': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gUserSingleNotifsEnabled = YES;
                TVLog(@"CLI: Single user notifications enabled (-i %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gUserSingleNotifsEnabled = NO;
                TVLog(@"CLI: Single user notifications disabled (-i %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -i value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'H': {
            long hp = strtol(optarg ? optarg : "0", NULL, 10);
            if (hp < 0 || hp > 65535) {
                TVPrintError("Invalid HTTP port: %s (expected 0..65535)", optarg);
                exit(EXIT_FAILURE);
            }
            gHttpPort = (int)hp;
            TVLog(@"CLI: HTTP port set to %d (-H)", gHttpPort);
            break;
        }
        case 'D': {
            const char *path = optarg ? optarg : "";
            if (!path || path[0] != '/') {
                TVPrintError("Invalid httpDir path for -D: %s (must be absolute)", path);
                exit(EXIT_FAILURE);
            }
            gHttpDirOverride = strdup(path);
            TVLog(@"CLI: HTTP dir override set to %s (-D)", path);
            break;
        }
        case 'e': {
            const char *path = optarg ? optarg : "";
            if (!path || !*path) {
                TVPrintError("Invalid value for -e (sslcertfile)");
                exit(EXIT_FAILURE);
            }
            gSslCertPath = strdup(path);
            TVLog(@"CLI: SSL cert file set (-e %s)", path);
            break;
        }
        case 'k': {
            const char *path = optarg ? optarg : "";
            if (!path || !*path) {
                TVPrintError("Invalid value for -k (sslkeyfile)");
                exit(EXIT_FAILURE);
            }
            gSslKeyPath = strdup(path);
            TVLog(@"CLI: SSL key file set (-k %s)", path);
            break;
        }
        case 'B': {
            const char *val = optarg ? optarg : "on";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gBonjourEnabled = YES;
                TVLog(@"CLI: Bonjour advertisement enabled (-B %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gBonjourEnabled = NO;
                TVLog(@"CLI: Bonjour advertisement disabled (-B %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -B value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'T': {
            const char *val = optarg ? optarg : "off";
            if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0) {
                gFileTransferEnabled = YES;
                TVLog(@"CLI: TightVNC 1.x file transfer extension enabled (-T %s)", [@(val) UTF8String]);
            } else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0) {
                gFileTransferEnabled = NO;
                TVLog(@"CLI: TightVNC 1.x file transfer extension disabled (-T %s)", [@(val) UTF8String]);
            } else {
                TVPrintError("Invalid -T value: %s (expected on|off|1|0|true|false)", val);
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 'V': {
            tvncVerboseLoggingEnabled = YES;
            TVLog(@"CLI: Verbose logging enabled (-V)");
            break;
        }
        case 'h':
        default: {
            printUsageAndExit(argv[0]);
            break;
        }
        }
    }

    // Reverse connection active -> override conflicting settings
    if (__reverseEnabled) {
        gPort = -1;    // disable listening port
        gHttpPort = 0; // disable HTTP server
        if (gHttpDirOverride) {
            free(gHttpDirOverride);
            gHttpDirOverride = NULL;
        }
        gBonjourEnabled = NO; // disable Bonjour when reverse is used
        TVLog(@"CLI: Reverse enabled -> port=-1, http=0, bonjour=off");
    }
}

#pragma mark - Display

static rfbScreenInfoPtr gScreen = NULL;
static void (^gFrameHandler)(CMSampleBufferRef) = nil;

static int gWidth = 0;
static int gHeight = 0;
static int gSrcWidth = 0;      // capture source width
static int gSrcHeight = 0;     // capture source height
static size_t gFBSize = 0;     // in bytes
static int gBytesPerPixel = 4; // ARGB/BGRA 32-bit

static void *gFrontBuffer = NULL; // Exposed to VNC clients via gScreen->frameBuffer
static void *gBackBuffer = NULL;  // We render into this and then swap

// Hash algorithm selection (auto: prefer CRC32 on ARM with hardware support)
#if DEBUG
#if defined(__aarch64__) || defined(__ARM_FEATURE_CRC32)
static const BOOL cUseCRC32Hash = YES;
#else
static const BOOL cUseCRC32Hash = NO;
#endif
#endif

typedef struct {
    int x, y, w, h;
} DirtyRect;

#if defined(__aarch64__) || defined(__ARM_FEATURE_CRC32)
NS_INLINE uint64_t crc32_update(uint64_t h, const uint8_t *data, size_t len) {
    uint32_t c = (uint32_t)h;
    const uint8_t *p = data;
    size_t n = len;
    // Process 8-byte chunks
    while (n >= 8) {
        uint64_t v;
        // Unaligned load is acceptable on ARM64; use memcpy to be safe for strict aliasing.
        memcpy(&v, p, sizeof(v));
        c = __builtin_arm_crc32d(c, v);
        p += 8;
        n -= 8;
    }
    if (n >= 4) {
        uint32_t v32;
        memcpy(&v32, p, sizeof(v32));
        c = __builtin_arm_crc32w(c, v32);
        p += 4;
        n -= 4;
    }
    if (n >= 2) {
        uint16_t v16;
        memcpy(&v16, p, sizeof(v16));
        c = __builtin_arm_crc32h(c, v16);
        p += 2;
        n -= 2;
    }
    if (n) {
        c = __builtin_arm_crc32b(c, *p);
    }
    return (uint64_t)c;
}
#else
NS_INLINE uint64_t fnv1a_basis(void) { return 1469598103934665603ULL; }
NS_INLINE uint64_t fnv1a_update(uint64_t h, const uint8_t *data, size_t len) {
    const uint64_t FNV_PRIME = 1099511628211ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= FNV_PRIME;
    }
    return h;
}
#endif

// Generic hash wrappers: prefer hardware CRC32 when enabled and available, else fallback to FNV-1a.
NS_INLINE uint64_t hash_basis(void) {
#if defined(__aarch64__) || defined(__ARM_FEATURE_CRC32)
    return 0u; // CRC32 initial accumulator
#else
    return fnv1a_basis();
#endif
}

NS_INLINE uint64_t hash_update(uint64_t h, const uint8_t *data, size_t len) {
#if defined(__aarch64__) || defined(__ARM_FEATURE_CRC32)
    return crc32_update(h, data, len);
#else
    // If CRC32 not supported at compile time, fallback to FNV-1a
    return fnv1a_update(h, data, len);
#endif
}

#pragma mark - Display Tiling

static int gTilesX = 0;
static int gTilesY = 0;
static size_t gTileCount = 0;
static uint64_t *gPrevHash = NULL;
static uint64_t *gCurrHash = NULL;
static uint8_t *gPendingDirty = NULL; // per-tile pending dirty mask
static BOOL gHasPending = NO;

static void initializeTilingOrReset(void) {
    int tilesX = (gWidth + gTileSize - 1) / gTileSize;
    int tilesY = (gHeight + gTileSize - 1) / gTileSize;
    size_t tileCount = (size_t)tilesX * (size_t)tilesY;

    if (tilesX != gTilesX || tilesY != gTilesY || tileCount != gTileCount || !gPrevHash || !gCurrHash) {
        free(gPrevHash);
        free(gCurrHash);

        if (gPendingDirty) {
            free(gPendingDirty);
            gPendingDirty = NULL;
        }

        gPrevHash = (uint64_t *)malloc(tileCount * sizeof(uint64_t));
        gCurrHash = (uint64_t *)malloc(tileCount * sizeof(uint64_t));
        gPendingDirty = (uint8_t *)malloc(tileCount);

        if (!gPrevHash || !gCurrHash) {
            TVPrintError("Out of memory for tile hashes");
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < tileCount; ++i) {
            gPrevHash[i] = 0; // force full update first frame
            gCurrHash[i] = hash_basis();
        }

        gTilesX = tilesX;
        gTilesY = tilesY;
        gTileCount = tileCount;

        if (gPendingDirty)
            memset(gPendingDirty, 0, gTileCount);
    } else {
        for (size_t i = 0; i < gTileCount; ++i) {
            gCurrHash[i] = hash_basis();
        }
    }
}

NS_INLINE void swapTileHashes(void) {
    uint64_t *tmp = gPrevHash;
    gPrevHash = gCurrHash;
    gCurrHash = tmp;
}

NS_INLINE void resetCurrTileHashes(void) {
    if (!gCurrHash || gTileCount == 0)
        return;
    uint64_t basis = hash_basis();
    for (size_t i = 0; i < gTileCount; ++i) {
        gCurrHash[i] = basis;
    }
}

// Accumulate pending dirty tiles for time-based coalescing
NS_INLINE void accumulatePendingDirty(void) {
    if (!gPendingDirty)
        return;

    for (size_t i = 0; i < gTileCount; ++i) {
        if (gCurrHash[i] != gPrevHash[i])
            gPendingDirty[i] = 1;
    }
}

NS_INLINE void hashTiledFromBuffer(const uint8_t *buf, int width, int height, size_t bpr) {
    resetCurrTileHashes();
    for (int y = 0; y < height; ++y) {
        int ty = y / gTileSize;
        for (int tx = 0; tx < gTilesX; ++tx) {
            int startX = tx * gTileSize;
            if (startX >= width)
                break;
            int endX = startX + gTileSize;
            if (endX > width)
                endX = width;
            size_t offset = (size_t)startX * (size_t)gBytesPerPixel;
            size_t length = (size_t)(endX - startX) * (size_t)gBytesPerPixel;
            size_t tileIndex = (size_t)ty * (size_t)gTilesX + (size_t)tx;
            gCurrHash[tileIndex] = hash_update(gCurrHash[tileIndex], buf + (size_t)y * bpr + offset, length);
        }
    }
}

// Sparse sampling hash: sample a subset of pixels per tile to reduce bandwidth.
NS_INLINE void hashTiledFromBufferSparse(const uint8_t *buf, int width, int height, size_t bpr, int sx, int sy) {
    if (sx < 1)
        sx = 1;
    if (sy < 1)
        sy = 1;
    resetCurrTileHashes();
    for (int y = 0; y < height; y += sy) {
        int ty = y / gTileSize;
        for (int tx = 0; tx < gTilesX; ++tx) {
            int startX = tx * gTileSize;
            if (startX >= width)
                break;
            int endX = startX + gTileSize;
            if (endX > width)
                endX = width;
            size_t tileIndex = (size_t)ty * (size_t)gTilesX + (size_t)tx;
            for (int x = startX; x < endX; x += sx) {
                const uint8_t *p = buf + (size_t)y * bpr + (size_t)x * (size_t)gBytesPerPixel;
                gCurrHash[tileIndex] = hash_update(gCurrHash[tileIndex], p, (size_t)gBytesPerPixel);
            }
            // Ensure last column contributes even if not aligned to stride
            int lastX = endX - 1;
            if (lastX >= startX && ((endX - startX - 1) % sx) != 0) {
                const uint8_t *p = buf + (size_t)y * bpr + (size_t)lastX * (size_t)gBytesPerPixel;
                gCurrHash[tileIndex] = hash_update(gCurrHash[tileIndex], p, (size_t)gBytesPerPixel);
            }
        }
    }
    // Also sample the last row if height-1 isn't covered by the stride
    int lastY = height - 1;
    if (lastY >= 0 && ((height - 1) % sy) != 0) {
        int ty = lastY / gTileSize;
        for (int tx = 0; tx < gTilesX; ++tx) {
            int startX = tx * gTileSize;
            if (startX >= width)
                break;
            int endX = startX + gTileSize;
            if (endX > width)
                endX = width;
            size_t tileIndex = (size_t)ty * (size_t)gTilesX + (size_t)tx;
            for (int x = startX; x < endX; x += sx) {
                const uint8_t *p = buf + (size_t)lastY * bpr + (size_t)x * (size_t)gBytesPerPixel;
                gCurrHash[tileIndex] = hash_update(gCurrHash[tileIndex], p, (size_t)gBytesPerPixel);
            }
            int lastX = endX - 1;
            if (lastX >= startX && ((endX - startX - 1) % sx) != 0) {
                const uint8_t *p = buf + (size_t)lastY * bpr + (size_t)lastX * (size_t)gBytesPerPixel;
                gCurrHash[tileIndex] = hash_update(gCurrHash[tileIndex], p, (size_t)gBytesPerPixel);
            }
        }
    }
}

// Parallel full hash over tiles: split by tile rows to reduce wall clock at flush.
NS_INLINE void hashTiledFromBufferParallel(const uint8_t *buf, int width, int height, size_t bpr, int threads) {
    if (threads <= 1) {
        hashTiledFromBuffer(buf, width, height, bpr);
        return;
    }
    resetCurrTileHashes();
    // Split by tile row bands
    int tilesY = gTilesY;
    if (tilesY <= 0)
        return;
    int bands = threads;
    if (bands > tilesY)
        bands = tilesY;
    dispatch_group_t grp = dispatch_group_create();
    for (int band = 0; band < bands; ++band) {
        dispatch_group_async(grp, dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            for (int ty = band; ty < tilesY; ty += bands) {
                int startY = ty * gTileSize;
                int endY = startY + gTileSize;
                if (startY >= height)
                    break;
                if (endY > height)
                    endY = height;
                for (int y = startY; y < endY; ++y) {
                    for (int tx = 0; tx < gTilesX; ++tx) {
                        int startX = tx * gTileSize;
                        if (startX >= width)
                            break;
                        int endX = startX + gTileSize;
                        if (endX > width)
                            endX = width;
                        size_t offset = (size_t)startX * (size_t)gBytesPerPixel;
                        size_t length = (size_t)(endX - startX) * (size_t)gBytesPerPixel;
                        size_t tileIndex = (size_t)ty * (size_t)gTilesX + (size_t)tx;
                        // Each tileIndex is updated by a single band (fixed ty), no race across bands.
                        gCurrHash[tileIndex] =
                            hash_update(gCurrHash[tileIndex], buf + (size_t)y * bpr + offset, length);
                    }
                }
            }
        });
    }
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
}

// Build dirty rectangles from tile hash diffs. Returns number of rects written, up to maxRects.
static int buildDirtyRects(DirtyRect *rects, int maxRects, int *outChangedTiles) {
    int rectCount = 0;
    int changedTiles = 0;

    // First pass: horizontal merge per tile row
    for (int ty = 0; ty < gTilesY; ++ty) {
        int tx = 0;
        while (tx < gTilesX) {
            size_t idx = (size_t)ty * (size_t)gTilesX + (size_t)tx;
            int changed = (gCurrHash[idx] != gPrevHash[idx]);
            if (!changed) {
                tx++;
                continue;
            }

            // Start of a run
            int runStart = tx;
            changedTiles++;
            tx++;
            while (tx < gTilesX) {
                size_t idx2 = (size_t)ty * (size_t)gTilesX + (size_t)tx;
                if (gCurrHash[idx2] != gPrevHash[idx2]) {
                    changedTiles++;
                    tx++;
                } else
                    break;
            }

            // Emit rect for this horizontal run
            if (rectCount < maxRects) {
                int x = runStart * gTileSize;
                int w = (tx - runStart) * gTileSize;
                int y = ty * gTileSize;
                int h = gTileSize;
                // Clip to screen bounds
                if (x + w > gWidth)
                    w = gWidth - x;
                if (y + h > gHeight)
                    h = gHeight - y;
                rects[rectCount++] = (DirtyRect){x, y, w, h};
            } else {
                // Too many rects; caller may fallback to fullscreen
                if (outChangedTiles)
                    *outChangedTiles = changedTiles;
                return rectCount;
            }
        }
    }

    // Optional vertical merge: merge rects with same x,w and contiguous vertically
    // Simple O(n^2) merge for small rect counts
    for (int i = 0; i < rectCount; ++i) {
        for (int j = i + 1; j < rectCount; ++j) {
            if (rects[j].w == 0 || rects[j].h == 0)
                continue;
            if (rects[i].x == rects[j].x && rects[i].w == rects[j].w) {
                if (rects[i].y + rects[i].h == rects[j].y) {
                    rects[i].h += rects[j].h;
                    rects[j].w = rects[j].h = 0; // mark removed
                } else if (rects[j].y + rects[j].h == rects[i].y) {
                    rects[j].h += rects[i].h;
                    rects[i].w = rects[i].h = 0;
                }
            }
        }
    }

    // Compact removed entries
    int k = 0;
    for (int i = 0; i < rectCount; ++i) {
        if (rects[i].w > 0 && rects[i].h > 0)
            rects[k++] = rects[i];
    }

    rectCount = k;
    if (outChangedTiles)
        *outChangedTiles = changedTiles;
    return rectCount;
}

// Build rects from pending mask by temporarily mapping to hashes
static int buildRectsFromPending(DirtyRect *rects, int maxRects) {
    if (!gPendingDirty)
        return 0;

    // Temporarily mark curr!=prev for pending tiles
    // Save originals
    // For efficiency, we only synthesize gCurrHash markers without touching buffers
    size_t changed = 0;
    for (size_t i = 0; i < gTileCount; ++i) {
        if (gPendingDirty[i]) {
            if (gCurrHash[i] == gPrevHash[i])
                gCurrHash[i] ^= 0x1ULL;
            changed++;
        }
    }

    int dummyTiles = 0;
    int cnt = buildDirtyRects(rects, maxRects, &dummyTiles);

    // Restore hashes for tiles we toggled
    for (size_t i = 0; i < gTileCount; ++i) {
        if (gPendingDirty[i]) {
            if (gCurrHash[i] == gPrevHash[i])
                gCurrHash[i] ^= 0x1ULL; // unlikely path
            else if ((gCurrHash[i] ^ 0x1ULL) == gPrevHash[i])
                gCurrHash[i] ^= 0x1ULL;
        }
    }

    (void)changed;
    return cnt;
}

NS_INLINE void markRectsModified(DirtyRect *rects, int rectCount) {
    for (int i = 0; i < rectCount; ++i) {
        rfbMarkRectAsModified(gScreen, rects[i].x, rects[i].y, rects[i].x + rects[i].w, rects[i].y + rects[i].h);
    }
}

NS_INLINE void copyRectsFromBackToFront(DirtyRect *rects, int rectCount) {
    size_t fbBPR = (size_t)gWidth * (size_t)gBytesPerPixel;
    for (int i = 0; i < rectCount; ++i) {
        int x = rects[i].x, y = rects[i].y, w = rects[i].w, h = rects[i].h;
        size_t rowBytes = (size_t)w * (size_t)gBytesPerPixel;
        for (int r = 0; r < h; ++r) {
            uint8_t *dst = (uint8_t *)gFrontBuffer + (size_t)(y + r) * fbBPR + (size_t)x * gBytesPerPixel;
            uint8_t *src = (uint8_t *)gBackBuffer + (size_t)(y + r) * fbBPR + (size_t)x * gBytesPerPixel;
            memcpy(dst, src, rowBytes);
        }
    }
}

#pragma mark - Display Hooks

static std::atomic<int> gInflight(0);

// Track encode life-cycle to provide backpressure via inflight counter
static void displayHook(rfbClientPtr cl) {
    (void)cl;
    gInflight.fetch_add(1, std::memory_order_relaxed);
}

static void displayFinishedHook(rfbClientPtr cl, int result) {
    (void)cl;
    (void)result;
    gInflight.fetch_sub(1, std::memory_order_relaxed);
}

static int setDesktopSizeHook(int width, int height, int numScreens, rfbExtDesktopScreen *extDesktopScreens,
                              rfbClientPtr cl) {
    (void)cl;
    (void)numScreens;
    (void)extDesktopScreens;
    [[ScreenCapturer sharedCapturer] forceNextFrameUpdate];
    // We do not support client-initiated resizing
    return rfbExtDesktopSize_ResizeProhibited;
}

#pragma mark - Display Tiling Constants

// Hashing performance controls
static const int cHashStrideX = 4;              // sparse sampling stride X (>=1; 1 = full scan)
static const int cHashStrideY = 4;              // sparse sampling stride Y (>=1; 1 = full scan)
static const BOOL cSparseHashDuringDefer = YES; // use sparse hashing while within defer window
// Skip vImage scaling when src/dst size difference is small; copy with pad/crop instead
static const int cNoScalePadThresholdPx = 8; // if both |dW| and |dH| <= this, do pad/crop copy

// Flush-time hashing optimization
static const BOOL cParallelHashOnFlush = YES; // use parallel hashing at flush to reduce wall time

#pragma mark - Frame Handlers

static std::atomic<int> gRotationQuad(0); // 0=0°, 1=90°, 2=180°, 3=270° (clockwise)
static void *gRotateScratch = NULL;       // rotation scratch (for 90°/270°)
static size_t gRotateScratchSize = 0;     // bytes
static void *gScaleTemp = NULL;           // vImage scale temp buffer
static size_t gScaleTempSize = 0;         // bytes

// Align width up to a multiple of 4 (helps encoders/clients). Preserve aspect by adjusting height.
NS_INLINE void alignDimensions(int rawW, int rawH, int *alignedW, int *alignedH) {
    if (rawW <= 0)
        rawW = 1;
    if (rawH <= 0)
        rawH = 1;
    // Round width up to next multiple of 4
    int w4 = (rawW + 3) & ~3;
    long long numer = (long long)rawH * (long long)w4;
    int hAdj = (int)((numer + rawW / 2) / rawW); // rounded to nearest
    if (hAdj <= 0)
        hAdj = 1;
    *alignedW = w4;
    *alignedH = hAdj;
}

// Resize framebuffer according to rotation (0/180 keep WxH from src, 90/270 swap), then apply scale
NS_INLINE void maybeResizeFramebufferForRotation(int rotQ) {
    // Source capture size (portrait-orientated)
    int srcW = gSrcWidth;
    int srcH = gSrcHeight;
    if (srcW <= 0 || srcH <= 0)
        return;

    // Rotate at source dimension stage
    int rotW = (rotQ % 2 == 0) ? srcW : srcH;
    int rotH = (rotQ % 2 == 0) ? srcH : srcW;

    // Apply output scaling then align width to multiple of 4 (adjust height to preserve aspect)
    int outWraw = (gScale > 0.0 && gScale < 1.0) ? MAX(1, (int)floor((double)rotW * gScale)) : rotW;
    int outHraw = (gScale > 0.0 && gScale < 1.0) ? MAX(1, (int)floor((double)rotH * gScale)) : rotH;
    int outW = 0, outH = 0;
    alignDimensions(outWraw, outHraw, &outW, &outH);

    if (outW == gWidth && outH == gHeight)
        return; // no change

    // Allocate new double buffers
    size_t newFBSize = (size_t)outW * (size_t)outH * (size_t)gBytesPerPixel;
    void *newFront = calloc(1, newFBSize);
    void *newBack = calloc(1, newFBSize);
    if (!newFront || !newBack) {
        TVPrintError("Failed to allocate required frame buffers");
        exit(EXIT_FAILURE);
    }

    // Swap buffers into screen & notify clients
    gWidth = outW;
    gHeight = outH;
    gFBSize = newFBSize;

    if (gScreen) {
        // Update server with new framebuffer
        rfbNewFramebuffer(gScreen, (char *)newFront, gWidth, gHeight, 8, 3, gBytesPerPixel);
        // Restore BGRA little-endian channel layout (R shift=16, G=8, B=0)
        int bps = 8;
        gScreen->serverFormat.redShift = bps * 2;   // 16
        gScreen->serverFormat.greenShift = bps * 1; // 8
        gScreen->serverFormat.blueShift = 0;        // 0
        gScreen->paddedWidthInBytes = gWidth * gBytesPerPixel;
    }

    // Free old buffers and store new pointers
    if (gFrontBuffer)
        free(gFrontBuffer);
    if (gBackBuffer)
        free(gBackBuffer);
    gFrontBuffer = newFront;
    gBackBuffer = newBack;

    // Keep gScreen->frameBuffer in sync (rfbNewFramebuffer already did, but ensure local)
    if (gScreen)
        gScreen->frameBuffer = (char *)gFrontBuffer;

    // Re-init tiling/hash state for new geometry
    initializeTilingOrReset();
    // Clear pending dirty flags to avoid carrying over old-geometry state into the new geometry
    if (gPendingDirty)
        memset(gPendingDirty, 0, gTileCount);

    gHasPending = NO;
    TVLog(@"Resize: framebuffer changed to %dx%d (rotQ=%d, scale=%.3f)", gWidth, gHeight, rotQ, gScale);
}

// Ensure scratch buffer for rotation is available and large enough
NS_INLINE int ensureRotateScratch(size_t w, size_t h) {
    size_t need = w * h * (size_t)gBytesPerPixel;
    if (need == 0)
        return -1;
    if (gRotateScratchSize >= need && gRotateScratch)
        return 0;
    void *nbuf = realloc(gRotateScratch, need);
    memset(nbuf, 0, need);
    if (!nbuf)
        return -1;
    gRotateScratch = nbuf;
    gRotateScratchSize = need;
    return 0;
}

NS_INLINE int ensureScaleTemp(size_t srcW, size_t srcH, size_t dstW, size_t dstH, vImage_Flags flags) {
    vImage_Buffer s = {.data = NULL,
                       .width = (vImagePixelCount)srcW,
                       .height = (vImagePixelCount)srcH,
                       .rowBytes = srcW * (size_t)gBytesPerPixel};
    vImage_Buffer d = {.data = NULL,
                       .width = (vImagePixelCount)dstW,
                       .height = (vImagePixelCount)dstH,
                       .rowBytes = dstW * (size_t)gBytesPerPixel};
    vImage_Error need = vImageScale_ARGB8888(&s, &d, NULL, flags | kvImageGetTempBufferSize);
    if (need < 0)
        return -1;
    size_t nbytes = (size_t)need;
    if (nbytes == 0)
        return 0;
    if (gScaleTempSize >= nbytes && gScaleTemp)
        return 0;
    void *nbuf = realloc(gScaleTemp, nbytes);
    memset(nbuf, 0, nbytes);
    if (!nbuf)
        return -1;
    gScaleTemp = nbuf;
    gScaleTempSize = nbytes;
    return 0;
}

// Row-by-row copy to convert a possibly-strided captured buffer into a tightly packed VNC buffer.
NS_INLINE void copyWithStrideTight(uint8_t *dstTight, const uint8_t *src, int width, int height,
                                   size_t srcBytesPerRow) {
    size_t dstBPR = (size_t)width * gBytesPerPixel;
    for (int y = 0; y < height; ++y) {
        memcpy(dstTight + (size_t)y * dstBPR, src + (size_t)y * srcBytesPerRow, dstBPR);
    }
}

// Copy with small pad/crop to avoid expensive scaling when sizes are close.
// Strategy:
// - Copy overlap region at (0,0) with width=min(srcW,dstW), height=min(srcH,dstH)
// - If dst wider, horizontally replicate the last pixel in each row to fill the right pad.
// - If dst taller, vertically replicate the last valid row to fill the bottom pad.
NS_INLINE void copyPadOrCropToTight(uint8_t *dstTight, int dstW, int dstH, const uint8_t *src, int srcW, int srcH,
                                    size_t srcBytesPerRow) {
    const int bpp = gBytesPerPixel;
    const size_t dstBPR = (size_t)dstW * (size_t)bpp;
    const int overlapW = srcW < dstW ? srcW : dstW;
    const int overlapH = srcH < dstH ? srcH : dstH;

    // 1) Copy overlap region row-by-row
    if (overlapW > 0 && overlapH > 0) {
        const size_t copyBytes = (size_t)overlapW * (size_t)bpp;
        for (int y = 0; y < overlapH; ++y) {
            uint8_t *drow = dstTight + (size_t)y * dstBPR;
            const uint8_t *srow = src + (size_t)y * srcBytesPerRow;
            memcpy(drow, srow, copyBytes);
            // 2) Right pad by replicating last pixel if needed
            if (dstW > overlapW) {
                const uint8_t *lastPx = (overlapW > 0) ? (drow + ((size_t)overlapW - 1) * (size_t)bpp) : drow;
                for (int x = overlapW; x < dstW; ++x) {
                    memcpy(drow + (size_t)x * (size_t)bpp, lastPx, (size_t)bpp);
                }
            }
        }
    }

    // 3) Bottom pad by replicating last valid row if needed
    if (dstH > overlapH) {
        uint8_t *lastRow = (overlapH > 0) ? (dstTight + (size_t)(overlapH - 1) * dstBPR) : dstTight;
        for (int y = overlapH; y < dstH; ++y) {
            uint8_t *drow = dstTight + (size_t)y * dstBPR;
            memcpy(drow, lastRow, dstBPR);
        }
    }
}

NS_INLINE void swapBuffers(void) {
    void *tmp = gFrontBuffer;
    gFrontBuffer = gBackBuffer;
    gBackBuffer = tmp;
    gScreen->frameBuffer = (char *)gFrontBuffer;
}

// Try to acquire all clients' sendMutex without blocking.
// Returns 1 on success and fills locked[] with acquired mutexes (count in *lockedCount),
// otherwise returns 0 and releases any partial locks.
static int tryLockAllClients(pthread_mutex_t **locked, size_t *lockedCount, size_t capacity) {
    *lockedCount = 0;
    rfbClientIteratorPtr it = rfbGetClientIterator(gScreen);
    rfbClientPtr cl;

    int ok = 1;
    while ((cl = rfbClientIteratorNext(it))) {
        if (*lockedCount >= capacity) {
            ok = 0;
            break;
        }
        pthread_mutex_t *m = &cl->sendMutex;
        if (pthread_mutex_trylock(m) == 0) {
            locked[(*lockedCount)++] = m;
        } else {
            ok = 0;
            break;
        }
    }

    rfbReleaseClientIterator(it);

    if (!ok) {
        // release any that were acquired
        for (size_t i = 0; i < *lockedCount; ++i) {
            pthread_mutex_unlock(locked[i]);
        }
        *lockedCount = 0;
        return 0;
    }

    return 1;
}

// Blocking lock helpers (original behavior): lock all clients, then unlock all.
NS_INLINE void lockAllClientsBlocking(void) {
    rfbClientIteratorPtr it = rfbGetClientIterator(gScreen);
    rfbClientPtr cl;
    while ((cl = rfbClientIteratorNext(it))) {
        pthread_mutex_lock(&cl->sendMutex);
    }
    rfbReleaseClientIterator(it);
}

NS_INLINE void unlockAllClientsBlocking(void) {
    rfbClientIteratorPtr it = rfbGetClientIterator(gScreen);
    rfbClientPtr cl;
    while ((cl = rfbClientIteratorNext(it))) {
        pthread_mutex_unlock(&cl->sendMutex);
    }
    rfbReleaseClientIterator(it);
}

static void handleFramebuffer(CMSampleBufferRef sampleBuffer) {

#if DEBUG
    // Perf: overall start timestamp
    CFAbsoluteTime __tv_tStart = CFAbsoluteTimeGetCurrent();
#endif

    CVPixelBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!pb) {
        TVLogVerbose(@"sampleBuffer has no image buffer (skip)");
        return;
    }

    // Busy-drop: if encoders are busy and limit reached, skip this frame (disabled when -Q 0)
    if (gMaxInflightUpdates > 0 && gInflight.load(std::memory_order_relaxed) >= gMaxInflightUpdates) {
        // When busy dropping, skip all hashing/dirty work.
        TVLogVerbose(@"drop frame due to inflight=%d >= limit=%d", gInflight.load(std::memory_order_relaxed),
                     gMaxInflightUpdates);
        return;
    }

#if DEBUG
    CFAbsoluteTime __tv_tLock0 = CFAbsoluteTimeGetCurrent();
#endif

    CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

#if DEBUG
    CFAbsoluteTime __tv_tLock1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msLock = (__tv_tLock1 - __tv_tLock0) * 1000.0;
    TVLogVerbose(@"lock pixel buffer took %.3f ms", __tv_msLock);
#endif

    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    const size_t srcBPR = (size_t)CVPixelBufferGetBytesPerRow(pb);
    const size_t width = (size_t)CVPixelBufferGetWidth(pb);
    const size_t height = (size_t)CVPixelBufferGetHeight(pb);

    // Determine rotation and resize framebuffer if orientation implies new dimensions.
    int rotQ = (gOrientationSyncEnabled ? gRotationQuad.load(std::memory_order_relaxed) : 0) & 3;

#if DEBUG
    CFAbsoluteTime __tv_tResize0 = CFAbsoluteTimeGetCurrent();
#endif

    maybeResizeFramebufferForRotation(rotQ);

#if DEBUG
    CFAbsoluteTime __tv_tResize1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msResize = (__tv_tResize1 - __tv_tResize0) * 1000.0;
    TVLogVerbose(@"maybeResize(rotQ=%d) took %.3f ms (server=%dx%d, src=%zux%zu)", rotQ, __tv_msResize, gWidth, gHeight,
                 width, height);
#endif

    if ((int)width != gWidth || (int)height != gHeight) {
        // With scaling enabled, this is expected; log once for info. Without scaling, warn once.
        static BOOL sLoggedSizeInfoOnce = NO;
        if (!sLoggedSizeInfoOnce) {
            sLoggedSizeInfoOnce = YES;
            if (gScale != 1.0) {
                TVLogVerbose(@"Scaling source %zux%zu -> output %dx%d (scale=%.3f)", width, height, gWidth, gHeight,
                             gScale);
            } else {
                TVLogVerbose(@"Captured frame size %zux%zu differs from server %dx%d; cropping/copying minimum region.",
                             width, height, gWidth, gHeight);
            }
        }
    }

    // Copy/Rotate/Scale into back buffer. ScreenCapturer is always portrait-oriented.
    // We rotate by UI orientation then scale to server size.
    BOOL dirtyDisabled = (gFullscreenThresholdPercent == 0);

    static int sLastRotQ = -1;
    bool rotationChanged = (sLastRotQ == -1) ? false : ((rotQ & 3) != (sLastRotQ & 3));
    bool needsRotate = (rotQ != 0);

    vImage_Buffer srcBuf = {
        .data = base, .height = (vImagePixelCount)height, .width = (vImagePixelCount)width, .rowBytes = srcBPR};

    vImage_Buffer stage = srcBuf; // after rotation
    vImage_Buffer rotBuf = {0};

#if DEBUG
    CFTimeInterval __tv_msRotate = 0.0;
    CFTimeInterval __tv_msScaleOrCopy = 0.0;
#endif

    if (needsRotate) {

#if DEBUG
        CFAbsoluteTime __tv_tRot0 = CFAbsoluteTimeGetCurrent();
#endif

        size_t rotW = (rotQ % 2 == 0) ? (size_t)width : (size_t)height;
        size_t rotH = (rotQ % 2 == 0) ? (size_t)height : (size_t)width;
        if (ensureRotateScratch(rotW, rotH) != 0) {
            CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
            return;
        }

        rotBuf.data = gRotateScratch;
        rotBuf.width = (vImagePixelCount)rotW;
        rotBuf.height = (vImagePixelCount)rotH;
        rotBuf.rowBytes = rotW * (size_t)gBytesPerPixel;

        uint8_t rotConst = kRotate0DegreesClockwise;
        switch (rotQ) {
        case 1:
            rotConst = kRotate90DegreesClockwise;
            break;
        case 2:
            rotConst = kRotate180DegreesClockwise;
            break;
        case 3:
            rotConst = kRotate270DegreesClockwise;
            break;
        default:
            rotConst = kRotate0DegreesClockwise;
            break;
        }

        uint8_t bg[4] = {0, 0, 0, 0};
        vImage_Error rerr = vImageRotate90_ARGB8888(&srcBuf, &rotBuf, rotConst, bg, kvImageNoFlags);
        if (rerr != kvImageNoError) {
            static BOOL sLoggedRotErrOnce = NO;
            if (!sLoggedRotErrOnce) {
                sLoggedRotErrOnce = YES;
                TVLog(@"vImageRotate90_ARGB8888 failed: %ld", (long)rerr);
            }

            CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
            return;
        }

        stage = rotBuf;

#if DEBUG
        CFAbsoluteTime __tv_tRot1 = CFAbsoluteTimeGetCurrent();
        __tv_msRotate = (__tv_tRot1 - __tv_tRot0) * 1000.0;
        TVLogVerbose(@"rotate %d*90 took %.3f ms (rotW=%zu, rotH=%zu)", rotQ, __tv_msRotate, (size_t)rotBuf.width,
                     (size_t)rotBuf.height);
#endif
    }

    // Scale stage to back buffer (tightly packed)
    vImage_Buffer dstBuf = {.data = gBackBuffer,
                            .height = (vImagePixelCount)gHeight,
                            .width = (vImagePixelCount)gWidth,
                            .rowBytes = (size_t)gWidth * (size_t)gBytesPerPixel};
    if (stage.width == dstBuf.width && stage.height == dstBuf.height && gScale == 1.0) {

#if DEBUG
        CFAbsoluteTime __tv_tCopy0 = CFAbsoluteTimeGetCurrent();
#endif

        copyWithStrideTight((uint8_t *)dstBuf.data, (const uint8_t *)stage.data, gWidth, gHeight, stage.rowBytes);

#if DEBUG
        CFAbsoluteTime __tv_tCopy1 = CFAbsoluteTimeGetCurrent();
        __tv_msScaleOrCopy = (__tv_tCopy1 - __tv_tCopy0) * 1000.0;
        TVLogVerbose(@"copy stage->back (tight) took %.3f ms", __tv_msScaleOrCopy);
#endif

    } else {

        // Small-diff pad/crop fast path to avoid vImageScale when sizes are close
        int dW = (int)dstBuf.width - (int)stage.width;
        int dH = (int)dstBuf.height - (int)stage.height;
        if (cNoScalePadThresholdPx > 0 && dW <= cNoScalePadThresholdPx && dW >= -cNoScalePadThresholdPx &&
            dH <= cNoScalePadThresholdPx && dH >= -cNoScalePadThresholdPx) {

#if DEBUG
            CFAbsoluteTime __tv_tPad0 = CFAbsoluteTimeGetCurrent();
#endif

            copyPadOrCropToTight((uint8_t *)dstBuf.data, (int)dstBuf.width, (int)dstBuf.height,
                                 (const uint8_t *)stage.data, (int)stage.width, (int)stage.height, stage.rowBytes);

#if DEBUG
            CFAbsoluteTime __tv_tPad1 = CFAbsoluteTimeGetCurrent();
            __tv_msScaleOrCopy = (__tv_tPad1 - __tv_tPad0) * 1000.0;
            TVLogVerbose(@"pad/crop copy stage->back took %.3f ms (stage=%zux%zu -> dst=%dx%d, thr=%d)",
                         __tv_msScaleOrCopy, (size_t)stage.width, (size_t)stage.height, gWidth, gHeight,
                         cNoScalePadThresholdPx);
#endif

        } else {

#if DEBUG
            CFAbsoluteTime __tv_tScale0 = CFAbsoluteTimeGetCurrent();
#endif

            if (ensureScaleTemp(stage.width, stage.height, dstBuf.width, dstBuf.height, kvImageHighQualityResampling) !=
                0) {
                CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                return;
            }

            vImage_Error err = vImageScale_ARGB8888(&stage, &dstBuf, gScaleTemp, kvImageHighQualityResampling);
            if (err != kvImageNoError) {
                static BOOL sLoggedVImageErrOnce = NO;
                if (!sLoggedVImageErrOnce) {
                    sLoggedVImageErrOnce = YES;
                    TVLog(@"vImageScale_ARGB8888 failed: %ld", (long)err);
                }
                CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
                return;
            }

#if DEBUG
            CFAbsoluteTime __tv_tScale1 = CFAbsoluteTimeGetCurrent();
            __tv_msScaleOrCopy = (__tv_tScale1 - __tv_tScale0) * 1000.0;
            TVLogVerbose(@"scale stage->back took %.3f ms (stage=%zux%zu -> dst=%dx%d)", __tv_msScaleOrCopy,
                         (size_t)stage.width, (size_t)stage.height, gWidth, gHeight);
#endif
        }
    }

#if DEBUG
    CFAbsoluteTime __tv_tUnlock0 = CFAbsoluteTimeGetCurrent();
#endif

    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

#if DEBUG
    CFAbsoluteTime __tv_tUnlock1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msUnlock = (__tv_tUnlock1 - __tv_tUnlock0) * 1000.0;
    TVLogVerbose(@"unlock pixel buffer took %.3f ms", __tv_msUnlock);
#endif

    // If rotation just changed, force a full-screen update and reset dirty state
    // to avoid mixing hashes/pending dirties from the previous orientation.
    if (rotationChanged) {
        // Clear pending mask/state
        if (gPendingDirty)
            memset(gPendingDirty, 0, gTileCount);
        gHasPending = NO;

#if DEBUG
        CFAbsoluteTime __tv_tSwap0 = CFAbsoluteTimeGetCurrent();
#endif

        if (gAsyncSwapEnabled) {
            pthread_mutex_t *locked[64];
            size_t lockedCount = 0;
            if (tryLockAllClients(locked, &lockedCount, sizeof(locked) / sizeof(locked[0]))) {
                swapBuffers();
                for (size_t i = 0; i < lockedCount; ++i)
                    pthread_mutex_unlock(locked[i]);
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"rotationChanged async-swap+mark fullscreen took %.3f ms",
                             (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif

            } else {
                copyWithStrideTight((uint8_t *)gFrontBuffer, (uint8_t *)gBackBuffer, gWidth, gHeight,
                                    (size_t)gWidth * (size_t)gBytesPerPixel);
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"rotationChanged copy(fullscreen)+mark took %.3f ms",
                             (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif
            }
        } else {
            lockAllClientsBlocking();
            swapBuffers();
            rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);
            unlockAllClientsBlocking();

#if DEBUG
            CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
            TVLogVerbose(@"rotationChanged blocking-swap+mark fullscreen took %.3f ms",
                         (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif
        }

        // Skip dirty detection for this frame after rotation; return early
        sLastRotQ = rotQ;

        // Rotation may not change geometry (0<->180). Maintain hashes here so
        // the next frame recomputes curr and swaps to form a clean baseline.
        resetCurrTileHashes();
        swapTileHashes();

#if DEBUG
        CFAbsoluteTime __tv_tEnd = CFAbsoluteTimeGetCurrent();
        TVLogVerbose(@"rotationChanged summary rotQ=%d lock=%.3fms resize=%.3fms rotate=%.3fms scale/copy=%.3fms "
                     @"total=%.3fms",
                     rotQ, __tv_msLock, __tv_msResize, __tv_msRotate, __tv_msScaleOrCopy,
                     (__tv_tEnd - __tv_tStart) * 1000.0);
#endif

        return;
    }

    // If dirty detection is disabled, perform a full-screen update
    if (dirtyDisabled) {

#if DEBUG
        CFAbsoluteTime __tv_tSwap0 = CFAbsoluteTimeGetCurrent();
#endif

        if (gAsyncSwapEnabled) {
            pthread_mutex_t *locked[64];
            size_t lockedCount = 0;
            if (tryLockAllClients(locked, &lockedCount, sizeof(locked) / sizeof(locked[0]))) {
                swapBuffers();
                for (size_t i = 0; i < lockedCount; ++i)
                    pthread_mutex_unlock(locked[i]);
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"dirtyDisabled async-swap+mark fullscreen took %.3f ms",
                             (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif

            } else {
                // Whole screen copy fallback (tight -> tight)
                copyWithStrideTight((uint8_t *)gFrontBuffer, (uint8_t *)gBackBuffer, gWidth, gHeight,
                                    (size_t)gWidth * (size_t)gBytesPerPixel);
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"dirtyDisabled copy(fullscreen)+mark took %.3f ms", (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif
            }
        } else {
            // Blocking swap to avoid tearing
            lockAllClientsBlocking();
            swapBuffers();
            rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);
            unlockAllClientsBlocking();

#if DEBUG
            CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
            TVLogVerbose(@"dirtyDisabled blocking-swap+mark fullscreen took %.3f ms",
                         (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif
        }

#if DEBUG
        CFAbsoluteTime __tv_tEnd = CFAbsoluteTimeGetCurrent();
        TVLogVerbose(
            @"dirtyDisabled summary rotQ=%d lock=%.3fms resize=%.3fms rotate=%.3fms scale/copy=%.3fms total=%.3fms",
            rotQ, __tv_msLock, __tv_msResize, __tv_msRotate, __tv_msScaleOrCopy, (__tv_tEnd - __tv_tStart) * 1000.0);
#endif

        return;
    }

    // Build dirty rectangles with deferred coalescing window (enabled)
    // Lightweight hashing to update pending and decide whether to flush.

#if DEBUG
    CFAbsoluteTime __tv_tHash0 = CFAbsoluteTimeGetCurrent();
#endif

    if (cSparseHashDuringDefer && gDeferWindowSec > 0) {
        hashTiledFromBufferSparse((const uint8_t *)gBackBuffer, gWidth, gHeight,
                                  (size_t)gWidth * (size_t)gBytesPerPixel, cHashStrideX, cHashStrideY);
    } else {
        resetCurrTileHashes();
        hashTiledFromBuffer((const uint8_t *)gBackBuffer, gWidth, gHeight, (size_t)gWidth * (size_t)gBytesPerPixel);
    }

#if DEBUG
    CFAbsoluteTime __tv_tHash1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msHash = (__tv_tHash1 - __tv_tHash0) * 1000.0;
    TVLogVerbose(@"tile hashing took %.3f ms (tiles=%zu, tileSize=%d)%@%@", __tv_msHash, gTileCount, gTileSize,
                 (cSparseHashDuringDefer && gDeferWindowSec > 0) ? @" [sparse]" : @"",
                 cUseCRC32Hash ? @" [crc32]" : @" [fnv]");
#endif

    enum { kRectBuf = 1024 };
    DirtyRect rects[kRectBuf];
    int changedTiles = 0;

    // Accumulate pending dirty tiles

#if DEBUG
    CFAbsoluteTime __tv_tPend0 = CFAbsoluteTimeGetCurrent();
#endif

    accumulatePendingDirty();

#if DEBUG
    CFAbsoluteTime __tv_tPend1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msPend = (__tv_tPend1 - __tv_tPend0) * 1000.0;
    TVLogVerbose(@"accumulate pending took %.3f ms (hasPending=%@)", __tv_msPend, gHasPending ? @"YES" : @"NO");
#endif

    // Decide whether to flush now
    BOOL shouldFlush = YES;
    static CFAbsoluteTime sDeferStartTime = 0;
    if (gDeferWindowSec > 0) {
        if (!gHasPending) {
            gHasPending = YES;
            sDeferStartTime = CFAbsoluteTimeGetCurrent();
            shouldFlush = NO; // start window, wait for more
        } else {
            CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
            shouldFlush = ((now - sDeferStartTime) >= gDeferWindowSec);
            TVLogVerbose(@"defer window elapsed=%.3f ms (threshold=%.3f ms) -> %@", (now - sDeferStartTime) * 1000.0,
                         gDeferWindowSec * 1000.0, shouldFlush ? @"FLUSH" : @"WAIT");
        }
    }

    int rectCount = 0;
    int changedPct = 0;
    BOOL fullScreen = NO;

    if (!shouldFlush) {
        // Still deferring: do not notify clients yet; keep previous full-hash baseline.

#if DEBUG
        CFAbsoluteTime __tv_tEnd = CFAbsoluteTimeGetCurrent();
        TVLogVerbose(@"deferred (no flush) summary rotQ=%d lock=%.3fms resize=%.3fms rotate=%.3fms scale/copy=%.3fms "
                     @"hash=%.3fms total=%.3fms",
                     rotQ, __tv_msLock, __tv_msResize, __tv_msRotate, __tv_msScaleOrCopy, __tv_msHash,
                     (__tv_tEnd - __tv_tStart) * 1000.0);
#endif

        return;
    }

    // At flush: recompute full hashes for precise rects
    {

#if DEBUG
        CFAbsoluteTime __tv_tHashFull0 = CFAbsoluteTimeGetCurrent();
#endif

        if (cParallelHashOnFlush) {
            // Use number of logical CPUs as thread hint (capped)
            int threads = (int)[[NSProcessInfo processInfo] processorCount];
            if (threads < 2)
                threads = 2;
            if (threads > 8)
                threads = 8;
            hashTiledFromBufferParallel((const uint8_t *)gBackBuffer, gWidth, gHeight,
                                        (size_t)gWidth * (size_t)gBytesPerPixel, threads);
        } else {
            resetCurrTileHashes();
            hashTiledFromBuffer((const uint8_t *)gBackBuffer, gWidth, gHeight, (size_t)gWidth * (size_t)gBytesPerPixel);
        }

#if DEBUG
        CFAbsoluteTime __tv_tHashFull1 = CFAbsoluteTimeGetCurrent();
        __tv_msHash = (__tv_tHashFull1 - __tv_tHashFull0) * 1000.0;
        TVLogVerbose(@"tile hashing (flush full)%@ took %.3f ms (tiles=%zu, tileSize=%d)%@",
                     cParallelHashOnFlush ? @" [parallel]" : @"", __tv_msHash, gTileCount, gTileSize,
                     cUseCRC32Hash ? @" [crc32]" : @" [fnv]");
#endif
    }

// Promote pending tiles into rects
#if DEBUG
    CFAbsoluteTime __tv_tRects0 = CFAbsoluteTimeGetCurrent();
#endif

    rectCount = buildRectsFromPending(rects, MIN(gMaxRectsLimit, kRectBuf));

    // If anything from this frame is also new dirty not in pending, ensure included
    int extraTiles = 0;
    if (rectCount == 0) {
        rectCount = buildDirtyRects(rects, MIN(gMaxRectsLimit, kRectBuf), &changedTiles);
    } else {
        // Merge current frame dirties by re-running with hashes, bounded
        DirtyRect rectsNow[kRectBuf];
        int nowCount = buildDirtyRects(rectsNow, MIN(gMaxRectsLimit, kRectBuf), &extraTiles);

        // Simple append then vertical merge will compact later in pipeline
        int space = kRectBuf - rectCount;
        int take = nowCount < space ? nowCount : space;
        if (take > 0)
            memcpy(&rects[rectCount], rectsNow, (size_t)take * sizeof(DirtyRect));
        rectCount += take;
    }

    int totalTiles = (int)gTileCount;
    int totalChanged = changedTiles + extraTiles;
    changedPct = (totalTiles > 0) ? (totalChanged * 100 / totalTiles) : 100;

    if (rectCount >= gMaxRectsLimit) {
        // Collapse to bounding box
        int minX = gWidth, minY = gHeight, maxX = 0, maxY = 0;
        for (int i = 0; i < rectCount; ++i) {
            if (rects[i].w <= 0 || rects[i].h <= 0)
                continue;
            if (rects[i].x < minX)
                minX = rects[i].x;
            if (rects[i].y < minY)
                minY = rects[i].y;
            if (rects[i].x + rects[i].w > maxX)
                maxX = rects[i].x + rects[i].w;
            if (rects[i].y + rects[i].h > maxY)
                maxY = rects[i].y + rects[i].h;
        }

        rects[0] = (DirtyRect){minX, minY, maxX - minX, maxY - minY};
        rectCount = 1;

        TVLogVerbose(@"rects exceeded limit -> collapse to bbox");
    }

    fullScreen = (changedPct >= gFullscreenThresholdPercent) || rectCount == 0;

#if DEBUG
    CFAbsoluteTime __tv_tRects1 = CFAbsoluteTimeGetCurrent();
    CFTimeInterval __tv_msRects = (__tv_tRects1 - __tv_tRects0) * 1000.0;
    TVLogVerbose(@"build rects took %.3f ms (rects=%d, changedTiles=%d, extraTiles=%d, changedPct=%d%%, fsThresh=%d%%, "
                 @"fullscreen=%@)",
                 __tv_msRects, rectCount, changedTiles, extraTiles, changedPct, gFullscreenThresholdPercent,
                 fullScreen ? @"YES" : @"NO");
#endif

    // Clear pending
    if (gPendingDirty)
        memset(gPendingDirty, 0, gTileCount);

    gHasPending = NO;

#if DEBUG
    CFAbsoluteTime __tv_tSwap0 = CFAbsoluteTimeGetCurrent();
#endif

    if (gAsyncSwapEnabled) {
        // Try non-blocking swap with fallback to single-buffer copy.
        pthread_mutex_t *locked[64];
        size_t lockedCount = 0;

        if (tryLockAllClients(locked, &lockedCount, sizeof(locked) / sizeof(locked[0]))) {
            swapBuffers();
            for (size_t i = 0; i < lockedCount; ++i)
                pthread_mutex_unlock(locked[i]);
            if (fullScreen) {
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);
            } else {
                markRectsModified(rects, rectCount);
            }

#if DEBUG
            CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
            TVLogVerbose(@"async-swap+mark took %.3f ms (%@)", (__tv_tSwap1 - __tv_tSwap0) * 1000.0,
                         fullScreen ? @"fullscreen" : @"partial");
#endif

        } else {
            if (fullScreen) {
                // Whole screen copy fallback (tight -> tight)
                copyWithStrideTight((uint8_t *)gFrontBuffer, (uint8_t *)gBackBuffer, gWidth, gHeight,
                                    (size_t)gWidth * (size_t)gBytesPerPixel);
                rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"async path copy(fullscreen)+mark took %.3f ms", (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif

            } else {
                // Only copy dirty regions from back to front to reduce tearing and bandwidth
                copyRectsFromBackToFront(rects, rectCount);
                markRectsModified(rects, rectCount);

#if DEBUG
                CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
                TVLogVerbose(@"async path copy(dirty %d rects)+mark took %.3f ms", rectCount,
                             (__tv_tSwap1 - __tv_tSwap0) * 1000.0);
#endif
            }
        }
    } else {
        // Original blocking behavior to avoid tearing.
        lockAllClientsBlocking();
        swapBuffers();
        if (fullScreen) {
            rfbMarkRectAsModified(gScreen, 0, 0, gWidth, gHeight);
        } else {
            markRectsModified(rects, rectCount);
        }
        unlockAllClientsBlocking();

#if DEBUG
        CFAbsoluteTime __tv_tSwap1 = CFAbsoluteTimeGetCurrent();
        TVLogVerbose(@"blocking-swap+mark took %.3f ms (%@)", (__tv_tSwap1 - __tv_tSwap0) * 1000.0,
                     fullScreen ? @"fullscreen" : @"partial");
#endif
    }

    // Prepare for next frame: current hashes become previous
    swapTileHashes();
    sLastRotQ = rotQ;

#if DEBUG
    CFAbsoluteTime __tv_tEnd = CFAbsoluteTimeGetCurrent();
    TVLogVerbose(@"frame summary rotQ=%d lock=%.3fms resize=%.3fms rotate=%.3fms scale/copy=%.3fms hash=%.3fms "
                 @"rects=%.3fms total=%.3fms (rectCount=%d, changedPct=%d%%, fullscreen=%@, inflight=%d/%d)",
                 rotQ, __tv_msLock, __tv_msResize, __tv_msRotate, __tv_msScaleOrCopy, __tv_msHash, __tv_msRects,
                 (__tv_tEnd - __tv_tStart) * 1000.0, rectCount, changedPct, fullScreen ? @"YES" : @"NO",
                 gInflight.load(std::memory_order_relaxed), gMaxInflightUpdates);
#endif
}

#pragma mark - Event Handlers

NS_INLINE NSString *keysymToString(rfbKeySym ks) {
    // Alphanumeric and basic ASCII
    if ((ks >= 0x20 && ks <= 0x7E) || ks == ' ') {
        unichar ch = (unichar)ks;
        return [NSString stringWithCharacters:&ch length:1];
    }
    switch (ks) {
    case XK_Return:
    case XK_KP_Enter:
        return @"RETURN";
    case XK_Tab:
        return @"TAB";
    case XK_Escape:
        return @"ESCAPE";
    case XK_BackSpace:
        return @"BACKSPACE";
    case XK_Delete:
        return @"FORWARDDELETE";
    case XK_Insert:
        return @"INSERT";
    case XK_Home:
        return @"HOME";
    case XK_End:
        return @"END";
    case XK_Page_Up:
        return @"PAGEUP";
    case XK_Page_Down:
        return @"PAGEDOWN";
    case XK_Left:
        return @"LEFTARROW";
    case XK_Right:
        return @"RIGHTARROW";
    case XK_Up:
        return @"UPARROW";
    case XK_Down:
        return @"DOWNARROW";
    case XK_space:
        return @" ";
    case XK_Shift_L:
        return @"LEFTSHIFT";
    case XK_Shift_R:
        return @"RIGHTSHIFT";
    case XK_Control_L:
        return @"LEFTCONTROL";
    case XK_Control_R:
        return @"RIGHTCONTROL";
    // Modifier mapping depending on scheme
    case XK_Alt_L:
        return (gModMapScheme == 1) ? @"LEFTCOMMAND" : @"LEFTALT"; // Option or Command
    case XK_Alt_R:
        return (gModMapScheme == 1) ? @"RIGHTCOMMAND" : @"RIGHTALT"; // Option or Command
    case XK_ISO_Level3_Shift:
        return @"LEFTALT"; // macOS left Option often sent as ISO_Level3_Shift
    case XK_Mode_switch:
        return @"RIGHTALT"; // Mode switch often behaves like AltGr
    case XK_Meta_L:
        return (gModMapScheme == 1) ? @"LEFTALT" : @"LEFTCOMMAND"; // Option or Command
    case XK_Meta_R:
        return (gModMapScheme == 1) ? @"RIGHTALT" : @"RIGHTCOMMAND"; // Option or Command
    case XK_Super_L:
        return @"LEFTCOMMAND"; // Treat Super as Command in both schemes
    case XK_Super_R:
        return @"RIGHTCOMMAND";
    default:
        break;
    }
    // Function keys XK_F1..XK_F24
    if (ks >= XK_F1 && ks <= XK_F24) {
        int idx = (int)(ks - XK_F1) + 1;
        return [NSString stringWithFormat:@"F%d", idx];
    }
    return nil;
}

static void kbdAddEvent(rfbBool down, rfbKeySym keySym, rfbClientPtr cl) {
    (void)cl;
    if (gViewOnly)
        return;

    STHIDEventGenerator *gen = [STHIDEventGenerator sharedGenerator];

    // Map common XF86 multimedia/brightness keysyms to iOS HID events
    switch ((unsigned long)keySym) {
    // Brightness Up/Down
    case 0x1008ff02UL: // XF86MonBrightnessUp
        if (down)
            [gen displayBrightnessIncrementDown];
        else
            [gen displayBrightnessIncrementUp];
        return;
    case 0x1008ff03UL: // XF86MonBrightnessDown
        if (down)
            [gen displayBrightnessDecrementDown];
        else
            [gen displayBrightnessDecrementUp];
        return;
    // Volume/Mute
    case 0x1008ff13UL: // XF86AudioRaiseVolume
        if (down)
            [gen volumeIncrementDown];
        else
            [gen volumeIncrementUp];
        return;
    case 0x1008ff11UL: // XF86AudioLowerVolume
        if (down)
            [gen volumeDecrementDown];
        else
            [gen volumeDecrementUp];
        return;
    case 0x1008ff12UL: // XF86AudioMute
        if (down)
            [gen muteDown];
        else
            [gen muteUp];
        return;
    // Media keys: Previous / Play-Pause / Next (use Consumer usages)
    case 0x1008ff3eUL: // Map as Previous Track (per user observation)
        if (down)
            [gen otherConsumerUsageDown:kHIDUsage_Csmr_ScanPreviousTrack];
        else
            [gen otherConsumerUsageUp:kHIDUsage_Csmr_ScanPreviousTrack];
        return;
    case 0x1008ff14UL: // XF86AudioPlay (toggle Play/Pause)
        if (down)
            [gen otherConsumerUsageDown:kHIDUsage_Csmr_PlayOrPause];
        else
            [gen otherConsumerUsageUp:kHIDUsage_Csmr_PlayOrPause];
        return;
    case 0x1008ff97UL: // Map as Next Track (per user observation)
        if (down)
            [gen otherConsumerUsageDown:kHIDUsage_Csmr_ScanNextTrack];
        else
            [gen otherConsumerUsageUp:kHIDUsage_Csmr_ScanNextTrack];
        return;
    default:
        break;
    }

    NSString *keyStr = keysymToString(keySym);
    if (gKeyEventLogging && tvncLoggingEnabled) {
        const char *mapped = keyStr ? [keyStr UTF8String] : "(nil)";
        rfbLog("[key] %s keysym=0x%lx (%lu) mapped=%s\n", down ? "down" : " up ", (unsigned long)keySym,
               (unsigned long)keySym, mapped);
    }

    if (!keyStr)
        return;

    if (down)
        [gen keyDown:keyStr];
    else
        [gen keyUp:keyStr];
}

static void kbdReleaseAllKeys(rfbClientPtr cl) {
    (void)cl;
    if (gViewOnly)
        return;

    STHIDEventGenerator *gen = [STHIDEventGenerator sharedGenerator];
    [gen releaseEveryKeys];
}

NS_INLINE CGPoint vncPointToDevicePoint(int vx, int vy) {
    // Map from VNC framebuffer space (gWidth x gHeight, post-rotation & scaling)
    // back to device capture space (portrait, gSrcWidth x gSrcHeight), inverting rotation.
    int rotQ = (gOrientationSyncEnabled ? gRotationQuad.load(std::memory_order_relaxed) : 0) & 3;

#if !TARGET_IPHONE_SIMULATOR
    // On iPad, align input coordinates with an extra +270° CW rotation
    // (i.e., -90°) per corrected requirement.
    int effRotQ = (rotQ + (gShouldApplyOrientationFix ? 3 : 0)) & 3;
#else
    int effRotQ = rotQ;
#endif

    // Dimensions of the rotated (pre-scale) stage
    int rotW = (effRotQ % 2 == 0) ? gSrcWidth : gSrcHeight;
    int rotH = (effRotQ % 2 == 0) ? gSrcHeight : gSrcWidth;

    // Undo scaling from stage(rotW x rotH) -> VNC(gWidth x gHeight)
    double sx = (gWidth > 0) ? ((double)rotW / (double)gWidth) : 1.0;
    double sy = (gHeight > 0) ? ((double)rotH / (double)gHeight) : 1.0;
    double stX = sx * (double)vx;
    double stY = sy * (double)vy;

    // Clamp to stage bounds
    if (stX < 0)
        stX = 0;
    if (stY < 0)
        stY = 0;
    if (stX > (double)(rotW - 1))
        stX = (double)(rotW - 1);
    if (stY > (double)(rotH - 1))
        stY = (double)(rotH - 1);

    // Invert rotation: stage -> source portrait space
    double dx = 0.0, dy = 0.0;
    switch (effRotQ) {
    case 0: // identity
        dx = stX;
        dy = stY;
        break;
    case 1: // 90 CW: inverse of stageX=srcH-1-srcY, stageY=srcX -> srcX=stageY; srcY=srcH-1-stageX
        dx = stY;
        dy = (double)(gSrcHeight - 1) - stX;
        break;
    case 2: // 180: srcX = srcW-1 - stageX; srcY = srcH-1 - stageY
        dx = (double)(gSrcWidth - 1) - stX;
        dy = (double)(gSrcHeight - 1) - stY;
        break;
    case 3: // 270 CW (90 CCW): inverse of stageX=srcY, stageY=srcW-1-srcX -> srcX=srcW-1-stageY; srcY=stageX
        dx = (double)(gSrcWidth - 1) - stY;
        dy = stX;
        break;
    }

    // Final clamp to device bounds
    if (dx < 0)
        dx = 0;
    if (dy < 0)
        dy = 0;
    if (dx > (double)(gSrcWidth - 1))
        dx = (double)(gSrcWidth - 1);
    if (dy > (double)(gSrcHeight - 1))
        dy = (double)(gSrcHeight - 1);

    return CGPointMake((CGFloat)dx, (CGFloat)dy);
}

@interface STHIDEventGenerator (Private)
- (void)touchDownAtPoints:(CGPoint *)locations touchCount:(NSUInteger)touchCount;
- (void)liftUpAtPoints:(CGPoint *)locations touchCount:(NSUInteger)touchCount;
- (void)_updateTouchPoints:(CGPoint *)points count:(NSUInteger)count;
@end

#define CLIENT_ID_LEN 8

// Per-client state stored in cl->clientData to avoid cross-client conflicts.
typedef struct {
    int lastButtonMask;                // last received pointer button mask from this client
    double wheelAccumPx;               // accumulated scroll in pixels (+down, -up) for this client
    BOOL wheelFlushScheduled;          // whether a flush is pending for this client
    BOOL isRepeaterClient;             // whether this client is a repeater
    char clientId8[CLIENT_ID_LEN + 1]; // cached 8-char client id (NUL-terminated)
} TVClientState;

NS_INLINE TVClientState *tvGetClientState(rfbClientPtr cl) { return cl ? (TVClientState *)cl->clientData : NULL; }

static dispatch_queue_t gWheelQueue = nil; // serial queue for wheel gestures

static void wheelScheduleFlush(rfbClientPtr cl, CGPoint anchorPoint, double delaySec, int rotQ) {
    TVClientState *st = tvGetClientState(cl);
    if (!st)
        return;

    if (gWheelStepPx <= 0) { // disabled
        st->wheelAccumPx = 0.0;
        st->wheelFlushScheduled = NO;
        return;
    }

    // Ensure client remains valid during delayed execution
    rfbIncrClientRef(cl);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delaySec * NSEC_PER_SEC)), gWheelQueue, ^{
        TVClientState *st2 = tvGetClientState(cl);
        if (!st2) {
            rfbDecrClientRef(cl);
            return;
        }

        // Consume the entire accumulation in one gesture to avoid many small drags.
        double takeRaw = st2->wheelAccumPx;
        st2->wheelAccumPx = 0.0; // zero out
        st2->wheelFlushScheduled = NO;
        double mag = fabs(takeRaw);
        if (mag < 1.0) {
            rfbDecrClientRef(cl);
            return;
        }

        // Velocity-like amplification: for larger accumulations (faster wheel),
        // slightly increase distance instead of emitting many short drags.
        double amp = 1.0 + fmin(gWheelAmpCap, gWheelAmpCoeff * log1p(mag / fmax(gWheelStepPx, 1.0)));
        double take = copysign(mag * amp, takeRaw);

        // Guarantee a small-but-meaningful movement for tiny scrolls
        if (fabs(take) < (gWheelMinTakeRatio * gWheelStepPx)) {
            take = copysign(gWheelMinTakeRatio * gWheelStepPx, take);
        }

        // Absolute clamp for safety
        double absClamp = gWheelMaxStepPx * gWheelAbsClampFactor;
        if (take > absClamp)
            take = absClamp;
        if (take < -absClamp)
            take = -absClamp;

        // Map VNC-vertical delta into device axis based on rotation
        CGFloat dx = 0, dy = 0;
        switch (rotQ & 3) {
        case 0: // portrait
            dx = 0;
            dy = (CGFloat)take;
            break;
        case 2: // upside-down
            dx = 0;
            dy = (CGFloat)(-take);
            break;
        case 1: // landscape left (90 CW)
            dx = (CGFloat)(+take);
            dy = 0;
            break;
        case 3: // landscape right (270 CW)
            dx = (CGFloat)(-take);
            dy = 0;
            break;
        }

        CGFloat endX = anchorPoint.x + dx;
        CGFloat endY = anchorPoint.y + dy;
        if (endX < 0)
            endX = 0;
        CGFloat maxX = (CGFloat)gSrcWidth - 1;
        if (endX > maxX)
            endX = maxX;
        if (endY < 0)
            endY = 0;
        CGFloat maxY = (CGFloat)gSrcHeight - 1;
        if (endY > maxY)
            endY = maxY;
        CGPoint endPt = CGPointMake(endX, endY);

        // Duration scales sub-linearly with distance; parameters configurable
        double dur = gWheelDurBase + gWheelDurK * sqrt(fabs(take));
        if (dur > gWheelDurMax)
            dur = gWheelDurMax;
        if (dur < gWheelDurMin)
            dur = gWheelDurMin;

        [[STHIDEventGenerator sharedGenerator] dragLinearWithStartPoint:anchorPoint endPoint:endPt duration:dur];

        rfbDecrClientRef(cl);
    });
}

static void ptrAddEvent(int buttonMask, int x, int y, rfbClientPtr cl) {
    if (gViewOnly)
        return;

    STHIDEventGenerator *gen = [STHIDEventGenerator sharedGenerator];
    CGPoint pt = vncPointToDevicePoint(x, y);

    TVClientState *st = tvGetClientState(cl);
    int lastMask = st ? st->lastButtonMask : 0;

    // Left button (bit 0)
    bool leftNow = (buttonMask & 1) != 0;
    bool leftPrev = (lastMask & 1) != 0;
    if (leftNow && !leftPrev) {
        [gen touchDownAtPoints:&pt touchCount:1];
    } else if (!leftNow && leftPrev) {
        [gen liftUpAtPoints:&pt touchCount:1];
    } else if (leftNow) {
        CGPoint p = pt;
        [gen _updateTouchPoints:&p count:1];
    }

    // Middle button (bit 1 -> mask 2): map to Power key
    bool midNow = (buttonMask & 2) != 0;
    bool midPrev = (lastMask & 2) != 0;
    if (midNow && !midPrev) {
        [gen powerDown];
    } else if (!midNow && midPrev) {
        [gen powerUp];
    }

    // Right button (bit 2 -> mask 4): map to Home/Menu key
    bool rightNow = (buttonMask & 4) != 0;
    bool rightPrev = (lastMask & 4) != 0;
    if (rightNow && !rightPrev) {
        [gen menuDown];
    } else if (!rightNow && rightPrev) {
        [gen menuUp];
    }

    // Wheel emulation: coalesce ticks and perform async flicks off the VNC thread.
    bool wheelUpNow = (buttonMask & 8) != 0;  // button 4
    bool wheelDnNow = (buttonMask & 16) != 0; // button 5
    bool wheelUpPrev = (lastMask & 8) != 0;
    bool wheelDnPrev = (lastMask & 16) != 0;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gWheelQueue = dispatch_queue_create("com.82flex.trollvnc.wheel", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    });

    if (gWheelStepPx > 0 && ((wheelUpNow && !wheelUpPrev) || (wheelDnNow && !wheelDnPrev))) {
        double delta = (wheelDnNow && !wheelDnPrev) ? +gWheelStepPx : -gWheelStepPx;
        if (gWheelNaturalDir)
            delta = -delta;
        int rotQ = (gOrientationSyncEnabled ? gRotationQuad.load(std::memory_order_relaxed) : 0) & 3;
        // Ensure client remains valid while we touch its state asynchronously
        rfbIncrClientRef(cl);
        dispatch_async(gWheelQueue, ^{
            TVClientState *st2 = tvGetClientState(cl);
            if (st2) {
                st2->wheelAccumPx += delta;
                if (!st2->wheelFlushScheduled) {
                    st2->wheelFlushScheduled = YES;
                    wheelScheduleFlush(cl, pt, gWheelCoalesceSec, rotQ);
                }
            }
            rfbDecrClientRef(cl);
        });
    }

    if (st)
        st->lastButtonMask = buttonMask;
}

#pragma mark - Bonjour (mDNS) Advertisement

static NSNetService *gBonjourService = nil;     // VNC service (_rfb._tcp.)
static NSNetService *gBonjourHttpService = nil; // Optional HTTP service (_http._tcp.)

// Compute a short, per-boot stable hash suffix (8 hex chars) from boot time
static NSString *tvBootHash8(void) {
    static NSString *suf = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Read boot time from the kernel (stable across process restarts in the same boot)
        struct timeval boottv = {0};
        size_t len = sizeof(boottv);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        int rc = sysctl(mib, 2, &boottv, &len, NULL, 0);

        uint64_t h = 1469598103934665603ULL; // FNV-1a 64-bit offset basis
        const uint64_t p = 1099511628211ULL; // prime
        if (rc == 0 && len == sizeof(boottv)) {
            uint64_t sec = (uint64_t)boottv.tv_sec;
            uint64_t usec = (uint64_t)boottv.tv_usec;
            for (int i = 0; i < 8; i++) {
                h ^= (uint8_t)((sec >> (i * 8)) & 0xFF);
                h *= p;
            }
            for (int i = 0; i < 8; i++) {
                h ^= (uint8_t)((usec >> (i * 8)) & 0xFF);
                h *= p;
            }
        } else {
            // Fallback: hash the monotonic uptime seconds (may vary between app restarts in same boot)
            uint64_t up_ms = (uint64_t)([NSProcessInfo processInfo].systemUptime * 1000.0);
            for (int i = 0; i < 8; i++) {
                h ^= (uint8_t)((up_ms >> (i * 8)) & 0xFF);
                h *= p;
            }
        }
        unsigned int shortHash = (unsigned int)(h & 0xFFFFFFFFu); // 32-bit
        suf = [NSString stringWithFormat:@"%08x", shortHash];
    });
    return suf;
}

// Compose Bonjour service name as gDesktopName + 8-char boot hash, clamped to 63 bytes
static NSString *tvBonjourServiceName(NSString *baseName) {
    NSString *name = baseName ?: @"TrollVNC";
    NSString *suffix = tvBootHash8();
    // mDNS single-label length limit is 63 bytes (UTF-8). We reserve suffix bytes.
    const NSUInteger maxBytes = 63;
    NSData *data = [name dataUsingEncoding:NSUTF8StringEncoding];
    // Reserve bytes for "-" + 8-char suffix (ASCII)
    NSUInteger reserve = suffix.length + 1; // hyphen + suffix
    if (reserve >= maxBytes) {
        // Pathological, but keep at least the suffix
        return suffix;
    }
    while (data.length + reserve > maxBytes && name.length > 0) {
        name = [name substringToIndex:name.length - 1];
        data = [name dataUsingEncoding:NSUTF8StringEncoding];
    }
    if (name.length == 0) {
        return suffix; // no space left for hyphen
    }
    return [NSString stringWithFormat:@"%@-%@", name, suffix];
}

@interface TVBonjourDelegate : NSObject <NSNetServiceDelegate>
@end

@implementation TVBonjourDelegate
- (void)netServiceDidPublish:(NSNetService *)sender {
    TVLog(@"Bonjour: published %@.%@:%ld", sender.name, sender.type, (long)sender.port);
}
- (void)netService:(NSNetService *)sender didNotPublish:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    TVLog(@"Bonjour: failed to publish %@.%@ (err=%@)", sender.name, sender.type, errorDict);
}
- (void)netServiceDidStop:(NSNetService *)sender {
    TVLog(@"Bonjour: stopped %@.%@", sender.name, sender.type);
}
@end

static TVBonjourDelegate *gBonjourDelegate = nil;

static NSData *bonjourTXTRecord(void) {
    // Minimal helpful metadata for clients
    // Keys kept short; values ASCII per convention
    NSMutableDictionary<NSString *, NSData *> *txt = [NSMutableDictionary dictionary];
    // Name
    if (gDesktopName.length > 0) {
        txt[@"vn"] = [gDesktopName dataUsingEncoding:NSUTF8StringEncoding];
    }
    // View-only flag
    txt[@"vo"] = [[NSString stringWithFormat:@"%d", gViewOnly ? 1 : 0] dataUsingEncoding:NSASCIIStringEncoding];
    // HTTP availability
    txt[@"hp"] = [[NSString stringWithFormat:@"%d", gHttpPort] dataUsingEncoding:NSASCIIStringEncoding];
    // FPS pref (if provided)
    if (gFpsMin || gFpsPref || gFpsMax) {
        NSString *fps = [NSString stringWithFormat:@"%d:%d:%d", gFpsMin, gFpsPref, gFpsMax];
        txt[@"fps"] = [fps dataUsingEncoding:NSASCIIStringEncoding];
    }
    return [NSNetService dataFromTXTRecordDictionary:txt];
}

static void refreshBonjourTXTRecord(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            refreshBonjourTXTRecord();
        });
        return;
    }
    if (!gBonjourService)
        return;
    [gBonjourService setTXTRecordData:bonjourTXTRecord()];
}

static void stopBonjour(void) {
    // NSNetService expects interactions on a runloop thread (prefer main).
    if (![NSThread isMainThread]) {
        dispatch_sync(dispatch_get_main_queue(), ^{
            stopBonjour();
        });
        return;
    }
    if (gBonjourService) {
        [gBonjourService stop];
        gBonjourService = nil;
    }
    if (gBonjourHttpService) {
        [gBonjourHttpService stop];
        gBonjourHttpService = nil;
    }
}

static void startBonjour(void) {
    // NSNetService expects interactions on a runloop thread (prefer main).
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            startBonjour();
        });
        return;
    }
    if (!gBonjourEnabled) {
        TVLog(@"Bonjour: disabled");
        return;
    }

    if (!gBonjourDelegate)
        gBonjourDelegate = [TVBonjourDelegate new];

    // Publish VNC service: _rfb._tcp. on gPort
    if (!gBonjourService) {
        NSString *svcName = tvBonjourServiceName(gDesktopName);
        gBonjourService = [[NSNetService alloc] initWithDomain:@"local." type:@"_rfb._tcp." name:svcName port:gPort];
        gBonjourService.delegate = gBonjourDelegate;
        [gBonjourService setTXTRecordData:bonjourTXTRecord()];
        [gBonjourService publish];
    } else {
        [gBonjourService stop];
        gBonjourService = nil;
        startBonjour();
        return;
    }

    // Optionally publish HTTP service when enabled
    if (gHttpPort > 0) {
        if (gBonjourHttpService) {
            [gBonjourHttpService stop];
            gBonjourHttpService = nil;
        }
        NSString *svcName = tvBonjourServiceName(gDesktopName);
        gBonjourHttpService = [[NSNetService alloc] initWithDomain:@"local."
                                                              type:@"_http._tcp."
                                                              name:svcName
                                                              port:gHttpPort];
        gBonjourHttpService.delegate = gBonjourDelegate;
        [gBonjourHttpService publish];
    }
}

#pragma mark - Control Socket

static int gTvCtlListenFd = -1;
static dispatch_source_t gTvCtlAcceptSource = NULL;

// Number of connected clients
static int gClientCount = 0;

// Subscribers for control change notifications (store as NSNumber wrapping fd)
static NSMutableSet<NSNumber *> *gTvCtlSubscribers = nil;
static dispatch_source_t gTvCtlDebounceTimer = NULL; // debounce timer for change notifications

// Global client states, populated via newClientHook/clientGoneHook.
// Key: 8-char client id; Value: immutable snapshot dictionary.
static NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *gClientStates = nil;

// Generate a stable-length 8-char id for a given socket fd (deterministic per fd).
static NSString *tvGenerateClientId8(int fd) {
    static uint64_t sSeed = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Mix boot hash and time for seed
        NSString *boot = tvBonjourServiceName(@""); // 8-char suffix only when baseName is empty
        uint64_t h = 1469598103934665603ULL;
        for (NSUInteger i = 0; i < boot.length; i++) {
            unichar c = [boot characterAtIndex:i];
            h ^= (uint8_t)(c & 0xFF);
            h *= 1099511628211ULL;
        }
        struct timeval tv;
        gettimeofday(&tv, NULL);
        h ^= (uint64_t)tv.tv_sec;
        h *= 1099511628211ULL;
        h ^= (uint64_t)tv.tv_usec;
        h *= 1099511628211ULL;
        sSeed = h;
    });
    uint64_t x = sSeed ^ (uint64_t)(uint32_t)fd;
    // xorshift mix to spread bits
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    uint32_t v = (uint32_t)(x & 0xFFFFFFFFu);
    return [NSString stringWithFormat:@"%08x", v];
}

static int tvSetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void tvStopControlSocket(void) {
    if (gTvCtlAcceptSource) {
        dispatch_source_cancel(gTvCtlAcceptSource);
        gTvCtlAcceptSource = NULL;
    }

    if (gTvCtlDebounceTimer) {
        dispatch_source_cancel(gTvCtlDebounceTimer);
        gTvCtlDebounceTimer = NULL;
    }

    // Close all subscriber sockets and clear set
    if (gTvCtlSubscribers) {
        @synchronized(gTvCtlSubscribers) {
            for (NSNumber *num in gTvCtlSubscribers) {
                int fd = [num intValue];
                if (fd >= 0)
                    close(fd);
            }
            [gTvCtlSubscribers removeAllObjects];
        }
    }

    if (gTvCtlListenFd >= 0) {
        close(gTvCtlListenFd);
        gTvCtlListenFd = -1;
    }
}

static void tvStartControlSocketIfNeeded(void) {
    if (!gTvCtlPort || isRepeaterEnabled())
        return;
    if (gTvCtlAcceptSource)
        return; // already started

    // Create listening socket bound to 127.0.0.1:gTvCtlPort
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        TVPrintError("Control socket: socket() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)gTvCtlPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        TVPrintError("Control socket: bind 127.0.0.1:%d failed: %s", gTvCtlPort, strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 8) < 0) {
        TVPrintError("Control socket: listen() failed: %s", strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (tvSetNonBlocking(fd) < 0) {
        TVPrintError("Control socket: failed to set O_NONBLOCK: %s", strerror(errno));
        // Continue anyway
    }

    gTvCtlListenFd = fd;

    static dispatch_queue_t sTVCtlQueue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sTVCtlQueue = dispatch_queue_create("com.82flex.trollvnc.control", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    });

    gTvCtlAcceptSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, sTVCtlQueue);
    // Helper forward declaration
    void tvCtlHandleConnection(int cfd, struct sockaddr_in caddr);
    dispatch_source_set_event_handler(gTvCtlAcceptSource, ^{
        for (;;) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(fd, (struct sockaddr *)&caddr, &clen);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                TVLog(@"Control socket: accept() error: %s", strerror(errno));
                break;
            }
            tvCtlHandleConnection(cfd, caddr);
        }
    });

    dispatch_source_set_cancel_handler(gTvCtlAcceptSource, ^{
        if (gTvCtlListenFd >= 0) {
            close(gTvCtlListenFd);
            gTvCtlListenFd = -1;
        }
    });

    dispatch_resume(gTvCtlAcceptSource);
    TVLog(@"Control socket listening on 127.0.0.1:%d (daemon=%@, repeater=%@)", gTvCtlPort,
          gIsDaemonMode ? @"YES" : @"NO", isRepeaterEnabled() ? @"YES" : @"NO");
}

// ---------- Control Protocol Implementation ----------

static void tvCtlWriteAll(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        p += (size_t)n;
        left -= (size_t)n;
    }
}

// --- Subscription helpers ---
static void tvCtlAddSubscriber(int fd) {
    if (fd < 0)
        return;
    (void)tvSetNonBlocking(fd);
#ifdef SO_NOSIGPIPE
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
#endif
    if (!gTvCtlSubscribers)
        gTvCtlSubscribers = [[NSMutableSet alloc] init];
    @synchronized(gTvCtlSubscribers) {
        [gTvCtlSubscribers addObject:@(fd)];
    }
    TVLog(@"Control socket: subscribed fd=%d (total=%lu)", fd, (unsigned long)gTvCtlSubscribers.count);
}

static void tvCtlRemoveSubscriber(int fd, BOOL closeFd) {
    if (!gTvCtlSubscribers)
        return;
    @synchronized(gTvCtlSubscribers) {
        [gTvCtlSubscribers removeObject:@(fd)];
    }
    if (closeFd && fd >= 0)
        close(fd);
    TVLog(@"Control socket: unsubscribed fd=%d", fd);
}

static void tvCtlBroadcastChanged(void) {
    if (!gTvCtlSubscribers || gTvCtlSubscribers.count == 0)
        return;
    const char *msg = "changed\n";
    size_t len = strlen(msg);
    NSMutableArray<NSNumber *> *dead = [NSMutableArray array];
    @synchronized(gTvCtlSubscribers) {
        for (NSNumber *num in gTvCtlSubscribers) {
            int fd = [num intValue];
            ssize_t n = send(fd, msg, len, 0);
            if (n != (ssize_t)len) {
                [dead addObject:num];
            }
        }
        if (dead.count) {
            for (NSNumber *num in dead) {
                int fd = [num intValue];
                (void)close(fd);
                [gTvCtlSubscribers removeObject:num];
            }
        }
    }
}

static void tvCtlScheduleBroadcastChanged(void) {
    // Coalesce rapid changes to ~150ms
    if (gTvCtlDebounceTimer) {
        dispatch_source_cancel(gTvCtlDebounceTimer);
        gTvCtlDebounceTimer = NULL;
    }

    dispatch_queue_t q = dispatch_get_main_queue();
    dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    gTvCtlDebounceTimer = t;

    uint64_t delayNs = (uint64_t)(150 * NSEC_PER_MSEC);
    dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, delayNs), DISPATCH_TIME_FOREVER, delayNs / 4);
    dispatch_source_set_event_handler(t, ^{
        tvCtlBroadcastChanged();
        if (gTvCtlDebounceTimer) {
            dispatch_source_cancel(gTvCtlDebounceTimer);
            gTvCtlDebounceTimer = NULL;
        }
    });

    dispatch_resume(t);
}

static NSArray *tvSnapshotClients(void) {
    // Build JSON-safe snapshot
    NSMutableArray *arr = [NSMutableArray array];
    if (!gClientStates)
        return arr;

    NSDate *now = [NSDate date];
    // No dedicated lock object earlier; guard with @synchronized on dictionary itself.
    @synchronized(gClientStates) {
        [gClientStates enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSDictionary *info, BOOL *stop) {
            (void)stop;
            NSString *cid = info[@"id"] ?: key;
            NSString *host = info[@"host"] ?: @"";
            NSNumber *viewOnly = info[@"viewOnly"] ?: @(NO);
            NSDate *connectAt = info[@"connectAt"];

            double t0 = connectAt ? [connectAt timeIntervalSince1970] : [now timeIntervalSince1970];
            double dur = [[NSNumber numberWithDouble:([now timeIntervalSince1970] - t0)] doubleValue];
            [arr addObject:@{
                @"id" : cid,
                @"host" : host,
                @"viewOnly" : viewOnly,
                @"connectedAt" : @(t0),
                @"durationSec" : @(dur)
            }];
        }];
    }

    return arr;
}

static NSData *tvCtlTSVForList(void) {
    NSArray *clients = tvSnapshotClients();
    NSMutableString *out = [NSMutableString string];

    // Header
    [out appendString:@"id\thost\tviewOnly\tconnectedAt\tdurationSec\n"];
    for (NSDictionary *c in clients) {
        NSString *cid = c[@"id"] ?: @"";
        NSString *host = c[@"host"] ?: @"";
        BOOL vo = [c[@"viewOnly"] boolValue];
        double t0 = [c[@"connectedAt"] doubleValue];
        double dur = [c[@"durationSec"] doubleValue];
        [out appendFormat:@"%@\t%@\t%@\t%.0f\t%.3f\n", cid, host, vo ? @"1" : @"0", t0, dur];
    }

    return [out dataUsingEncoding:NSUTF8StringEncoding];
}

static BOOL tvDisconnectClientById(NSString *cid, BOOL addToBlocklist) {
    if (!cid || cid.length == 0 || !gScreen)
        return NO;

    BOOL found = NO;
    rfbClientPtr cl = NULL;
    rfbClientIteratorPtr it = rfbGetClientIterator(gScreen);
    while ((cl = rfbClientIteratorNext(it))) {
        NSString *kid = tvGenerateClientId8(cl->sock);
        if (![kid isEqualToString:cid]) {
            continue;
        }

        found = YES;

        // Add to blocked hosts list if requested
        if (addToBlocklist) {
            do {
                NSString *host = (cl && cl->host) ? [NSString stringWithUTF8String:cl->host] : @"";
                if (!host.length) {
                    break;
                }

                if (!gBlockedHosts) {
                    gBlockedHosts = [[NSMutableSet alloc] init];
                }

                @synchronized(gBlockedHosts) {
                    [gBlockedHosts addObject:host];
                }

                TVLog(@"Blocked host: %@", host);
            } while (NO);
        }

        rfbCloseClient(cl);
        break;
    }

    rfbReleaseClientIterator(it);
    return found;
}

static NSData *tvCtlTextForKick(NSString *cid, BOOL addToBlocklist) {
    BOOL ok = tvDisconnectClientById(cid, addToBlocklist);
    const char *raw = ok ? "OK\n" : "NOT_FOUND\n";
    return [NSData dataWithBytes:raw length:strlen(raw)];
}

static BOOL tvDisconnectAllClients(void) {
    if (!gScreen)
        return NO;

    rfbClientPtr cl = NULL;
    rfbClientIteratorPtr it = rfbGetClientIterator(gScreen);
    while ((cl = rfbClientIteratorNext(it))) {
        rfbCloseClient(cl);
    }

    rfbReleaseClientIterator(it);
    return YES;
}

void tvCtlHandleConnection(int cfd, struct sockaddr_in caddr) {
    // Log peer and set short timeouts
    char ipbuf[INET_ADDRSTRLEN] = {0};
    const char *ip = inet_ntop(AF_INET, &caddr.sin_addr, ipbuf, sizeof(ipbuf));
    TVLog(@"Control socket: connection from %s:%d (fd=%d)", ip ? ip : "?", ntohs(caddr.sin_port), cfd);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Read a single line command
    uint8_t buf[1024];
    size_t off = 0;
    for (;;) {
        ssize_t n = recv(cfd, buf + off, sizeof(buf) - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        off += (size_t)n;
        if (off >= sizeof(buf))
            break;
        if (memchr(buf, '\n', off))
            break;
    }

    // Parse command
    NSString *cmd = [[NSString alloc] initWithBytes:buf length:off encoding:NSUTF8StringEncoding];
    if (!cmd)
        cmd = @"";
    cmd = [cmd stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSData *resp = nil;
    BOOL keepOpen = NO;
    if (cmd.length == 0) {
        resp = [@"ERR Empty\n" dataUsingEncoding:NSUTF8StringEncoding];
    } else if ([cmd isEqualToString:@"count"]) {
        NSString *s = [NSString stringWithFormat:@"%d\n", gClientCount];
        resp = [s dataUsingEncoding:NSUTF8StringEncoding];
    } else if ([cmd isEqualToString:@"list"]) {
        resp = tvCtlTSVForList();
    } else if ([cmd isEqualToString:@"subscribe on"]) {
        tvCtlAddSubscriber(cfd);
        const char *ok = "OK\n";
        resp = [NSData dataWithBytes:ok length:strlen(ok)];
        keepOpen = YES; // keep connection open for pushes
    } else if ([cmd isEqualToString:@"subscribe off"]) {
        tvCtlRemoveSubscriber(cfd, NO);
        const char *ok = "OK\n";
        resp = [NSData dataWithBytes:ok length:strlen(ok)];
    } else if ([cmd hasPrefix:@"disconnect "] || [cmd hasPrefix:@"kick "] || [cmd hasPrefix:@"block "]) {
        NSArray *parts = [cmd componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *cid = parts.count >= 2 ? parts[1] : @"";
        if ([cid isEqualToString:@"ALL"]) {
            tvDisconnectAllClients();
            resp = [@"OK\n" dataUsingEncoding:NSUTF8StringEncoding];
        } else if (cid.length != 8) {
            resp = [@"ERR InvalidID\n" dataUsingEncoding:NSUTF8StringEncoding];
        } else {
            BOOL shouldBlock = [cmd hasPrefix:@"block "];
            resp = tvCtlTextForKick(cid, shouldBlock);
        }
    } else {
        resp = [@"ERR Unknown\n" dataUsingEncoding:NSUTF8StringEncoding];
    }

    if (resp)
        tvCtlWriteAll(cfd, resp.bytes, resp.length);

    if (keepOpen) {
        // Do not close; subscriber lifecycle managed elsewhere
        return;
    }

    close(cfd);
}

#pragma mark - User Notifications

static void tvPublishUserSingleNotifs(void) {
    if (!gUserSingleNotifsEnabled || isRepeaterEnabled())
        return;

    BulletinManager *mgr = [BulletinManager sharedManager];

    if (gClientCount == 0) {
        dispatch_async(dispatch_get_main_queue(), ^(void) {
            [mgr revokeSingleNotification];
        });
        return;
    }

    NSDictionary *userInfo = @{
        @"clientCount" : @(gClientCount),
    };

    NSString *localizedContentTmpl;
    localizedContentTmpl = (gClientCount == 1) ? LocalizedString(@"There is %d active VNC client.", @"Localizable",
                                                                 tvLocalizationBundle(), @"trollvncserver")
                                               : LocalizedString(@"There are %d active VNC clients.", @"Localizable",
                                                                 tvLocalizationBundle(), @"trollvncserver");

    NSString *localizedContent = [NSString stringWithFormat:localizedContentTmpl, gClientCount];
    dispatch_async(dispatch_get_main_queue(), ^(void) {
        [mgr updateSingleBannerWithContent:localizedContent badgeCount:gClientCount userInfo:userInfo];
    });
}

static void tvPublishClientConnectedNotif(NSString *host) {
    if (!gUserClientNotifsEnabled || isRepeaterEnabled() || !host || host.length == 0)
        return;

    // Check if host is a loopback address
    if ([host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"::1"] || [host isEqualToString:@"localhost"] ||
        [host hasPrefix:@"127."] || [host hasPrefix:@"::ffff:127."]) {
        TVLog(@"Skipping notification for loopback connection from %@", host);
        return;
    }

    BulletinManager *mgr = [BulletinManager sharedManager];

    NSDictionary *userInfo = @{
        @"clientHost" : host,
    };

    NSString *localizedContentTmpl;
    localizedContentTmpl =
        LocalizedString(@"A VNC client connected from %@.", @"Localizable", tvLocalizationBundle(), @"trollvncserver");

    NSString *localizedContent = [NSString stringWithFormat:localizedContentTmpl, host];
    dispatch_async(dispatch_get_main_queue(), ^(void) {
        [mgr popBannerWithContent:localizedContent userInfo:userInfo];
    });
}

static void tvPublishClientDisconnectedNotif(NSString *host) {
    if (!gUserClientNotifsEnabled || !host || host.length == 0)
        return;

    BulletinManager *mgr = [BulletinManager sharedManager];

    NSDictionary *userInfo = @{
        @"clientHost" : host,
    };

    NSString *localizedContentTmpl;
    localizedContentTmpl = LocalizedString(@"A VNC client disconnected from %@.", @"Localizable",
                                           tvLocalizationBundle(), @"trollvncserver");

    NSString *localizedContent = [NSString stringWithFormat:localizedContentTmpl, host];
    dispatch_async(dispatch_get_main_queue(), ^(void) {
        [mgr popBannerWithContent:localizedContent userInfo:userInfo];
    });
}

#pragma mark - Client Handlers

static BOOL gIsCaptureStarted = NO;
static BOOL gIsClipboardStarted = NO;

#if !TARGET_OS_SIMULATOR
static BOOL gRestoreAssist = NO;
#endif

static void clientGoneHook(rfbClientPtr cl) {
    // Free per-client state
    TVClientState *st = tvGetClientState(cl);
    BOOL isRepeaterClient = NO;
    NSString *removeKey = nil;
    if (st) {
        isRepeaterClient = st->isRepeaterClient;
        if (st->clientId8[0] != '\0') {
            removeKey = [NSString stringWithUTF8String:st->clientId8];
        }
        free(st);
        cl->clientData = NULL;
    }

    // Remove by cached id (fallback to fd-derived if unavailable)
    if (!removeKey)
        removeKey = tvGenerateClientId8(cl->sock);
    if (removeKey && gClientStates) {
        @synchronized(gClientStates) {
            [gClientStates removeObjectForKey:removeKey];
        }
    }

    // Decrement client count and stop capture if this was the last client.
    if (gClientCount > 0)
        gClientCount--;

    NSString *host = (cl && cl->host) ? [NSString stringWithUTF8String:cl->host] : @"";
    TVLog(@"Client %@ disconnected, active clients=%d", host, gClientCount);

    if (gIsCaptureStarted && gClientCount == 0) {
        [[ScreenCapturer sharedCapturer] endCapture];
        gIsCaptureStarted = NO;
        TVLog(@"No clients remaining; screen capture stopped.");
    }

    if (gIsClipboardStarted && gClientCount == 0) {
        [[ClipboardManager sharedManager] stop];
        gIsClipboardStarted = NO;
        TVLog(@"No clients remaining; clipboard listening stopped.");
    }

#if !TARGET_OS_SIMULATOR
    // AutoAssist: disable AssistiveTouch if we enabled it and no clients remain
    if (gClientCount == 0 && gRestoreAssist) {
        gRestoreAssist = NO;
        [PSAssistiveTouchSettingsDetail setEnabled:NO];
    }
#endif

    // KeepAlive: disable when no clients remain
    if (gClientCount == 0) {
        [[STHIDEventGenerator sharedGenerator] setKeepAliveInterval:0];
        TVLog(@"No clients remaining; KeepAlive stopped.");
    }

    // Update TXT with possibly changed state (e.g., viewOnly unaffected, but keep consistent)
    refreshBonjourTXTRecord();

    // Notify subscribers after removal (debounced)
    tvCtlScheduleBroadcastChanged();

    // Update user notification
    tvPublishUserSingleNotifs();

    // Notify client disconnected
    tvPublishClientDisconnectedNotif(host);

    // Stop the main run loop if this was a repeater client
    if (isRepeaterClient) {
        CFRunLoopStop(CFRunLoopGetMain());
    }
}

static enum rfbNewClientAction newClientHook(rfbClientPtr cl) {
    cl->clientGoneHook = clientGoneHook;
    if (!cl->viewOnly && gViewOnly)
        cl->viewOnly = TRUE;

    // Allocate per-client state bag
    TVClientState *st = (TVClientState *)calloc(1, sizeof(TVClientState));
    if (st) {
        st->lastButtonMask = 0;
        st->wheelAccumPx = 0;
        st->wheelFlushScheduled = NO;
        st->clientId8[0] = '\0';
        cl->clientData = st;
    }

    gClientCount++;
    TVLog(@"Client connected, active clients=%d", gClientCount);

    // Add to global client states
    NSString *clientId = tvGenerateClientId8(cl->sock);
    if (st && clientId.length) {
        // Cache into fixed buffer
        const char *u8 = [clientId UTF8String];
        if (u8) {
            size_t n = strnlen(u8, 8);
            memcpy(st->clientId8, u8, n);
            st->clientId8[n] = '\0';
        }
    }
    NSString *host = (cl && cl->host) ? [NSString stringWithUTF8String:cl->host] : @"";
    NSDate *now = [NSDate date];
    NSDictionary *entry = @{
        @"id" : clientId,
        @"host" : host,
        @"viewOnly" : @(cl->viewOnly ? YES : NO),
        @"connectAt" : now,
    };

    if (!gClientStates)
        gClientStates = [[NSMutableDictionary alloc] init];
    gClientStates[clientId] = entry;

    // Update TXT (e.g., potential dynamic flags in future)
    refreshBonjourTXTRecord();

    // Notify subscribers (debounced)
    tvCtlScheduleBroadcastChanged();

    // Update user notification
    tvPublishUserSingleNotifs();

    // Notify client connected
    tvPublishClientConnectedNotif(host);

    if (!gIsCaptureStarted && gClientCount > 0 && gFrameHandler) {
        // Start capture when entering non-zero client population.
        gIsCaptureStarted = YES;
        [[ScreenCapturer sharedCapturer] startCaptureWithFrameHandler:gFrameHandler];
        TVLog(@"Screen capture started (clients=%d).", gClientCount);
    }

    if (gClipboardEnabled && !gIsClipboardStarted && gClientCount > 0) {
        gIsClipboardStarted = YES;
        [[ClipboardManager sharedManager] start];
        TVLog(@"Clipboard listening started (clients=%d).", gClientCount);
    }

#if !TARGET_OS_SIMULATOR
    // AutoAssist: enable AssistiveTouch if not already enabled
    if (gClientCount > 0 && gAutoAssistEnabled && ![PSAssistiveTouchSettingsDetail isEnabled]) {
        gRestoreAssist = YES;
        [PSAssistiveTouchSettingsDetail setEnabled:YES];
    }
#endif

    // KeepAlive: enable when at least one client is connected and interval > 0
    if (gClientCount > 0 && gKeepAliveSec > 0.0) {
        [[STHIDEventGenerator sharedGenerator] setKeepAliveInterval:gKeepAliveSec];
        TVLog(@"KeepAlive started with interval (%.3f sec)", gKeepAliveSec);
    }

    return RFB_CLIENT_ACCEPT;
}

#pragma mark - Clipboard Extension

static std::atomic<int> gClipboardSuppressSend(0); // >0 means suppress sending clipboard to clients

static void setXCutTextLatin1(char *str, int len, rfbClientPtr cl) {
    (void)cl;
    if (!str || len < 0)
        len = 0;

    TVLog(@"Clipboard: received client cut text (Latin-1) len=%d", len);
    NSData *data = [NSData dataWithBytes:str length:(NSUInteger)len];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    if (!s)
        s = @"";

    dispatch_async(dispatch_get_main_queue(), ^{
        gClipboardSuppressSend.fetch_add(1, std::memory_order_relaxed);

        TVLog(@"Clipboard: applying client text to UIPasteboard (Latin-1), suppression now=%d",
              gClipboardSuppressSend.load(std::memory_order_relaxed));
        [[ClipboardManager sharedManager] setStringFromRemote:s];

        gClipboardSuppressSend.fetch_sub(1, std::memory_order_relaxed);
    });
}

static void setXCutTextUTF8(char *str, int len, rfbClientPtr cl) {
    (void)cl;
    if (!str || len < 0)
        len = 0;

    TVLog(@"Clipboard: received client cut text (UTF-8) len=%d", len);

    NSData *data = [NSData dataWithBytes:str length:(NSUInteger)len];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) {
        // Fallback try Latin-1 if UTF-8 decode fails
        s = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        if (!s)
            s = @"";
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        gClipboardSuppressSend.fetch_add(1, std::memory_order_relaxed);

        TVLog(@"Clipboard: applying client text to UIPasteboard (UTF-8), suppression now=%d",
              gClipboardSuppressSend.load(std::memory_order_relaxed));
        [[ClipboardManager sharedManager] setStringFromRemote:s];

        gClipboardSuppressSend.fetch_sub(1, std::memory_order_relaxed);
    });
}

static void sendClipboardToClients(NSString *_Nullable text) {
    if (!gScreen) {
        TVLog(@"Clipboard: screen not initialized; skipping send");
        return;
    }

    if (!gClipboardEnabled) {
        TVLog(@"Clipboard: sync disabled; skipping send");
        return;
    }

    if (gClientCount <= 0) {
        TVLog(@"Clipboard: no connected clients; skipping send");
        return;
    }

    if (gClipboardSuppressSend.load(std::memory_order_relaxed) > 0) {
        TVLog(@"Clipboard: send suppressed (local set echo avoidance)");
        return; // suppressed (likely local set)
    }

    char *utf8 = NULL;
    int utf8Len = 0;
    char *latin1 = NULL;
    int latin1Len = 0;

    do {
        if (!text) {
            break;
        }

        // Prepare best-effort Latin-1 fallback
        NSData *latin1Data = [text dataUsingEncoding:NSISOLatin1StringEncoding allowLossyConversion:YES];
        latin1Len = (int)latin1Data.length;
        if (!latin1Len)
            break;

        latin1 = (char *)malloc((size_t)latin1Len);
        if (!latin1) {
            latin1Len = 0;
            break;
        }

        memcpy(latin1, [latin1Data bytes], (size_t)latin1Len);

    } while (0);

    do {
        if (!text) {
            break;
        }

        NSData *utf8Data = [text dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
        utf8Len = (int)utf8Data.length;
        if (!utf8Len)
            break;

        utf8 = (char *)malloc((size_t)utf8Len);
        if (!utf8) {
            utf8Len = 0;
            break;
        }

        memcpy(utf8, [utf8Data bytes], (size_t)utf8Len);

    } while (0);

    if (utf8 || latin1) {
        TVLog(@"Clipboard: sending to clients (utf8Len=%d, latin1Len=%d, clients=%d)", utf8Len, latin1Len,
              gClientCount);
    }

    if (utf8 && latin1) {
        rfbSendServerCutTextUTF8(gScreen, utf8, utf8Len, latin1, latin1Len);
    } else if (latin1) {
        rfbSendServerCutText(gScreen, latin1, latin1Len);
    } else {
        TVLog(@"Clipboard: no valid clipboard data to send");
    }

    if (utf8)
        free(utf8);

    if (latin1)
        free(latin1);
}

#pragma mark - Server-Side Cursor

NS_INLINE void setupXCursor(rfbScreenInfoPtr screen) {
    int width = 13, height = 11;

    const char cursor[] = "             "
                          " xx       xx "
                          "  xx     xx  "
                          "   xx   xx   "
                          "    xx xx    "
                          "     xxx     "
                          "    xx xx    "
                          "   xx   xx   "
                          "  xx     xx  "
                          " xx       xx "
                          "             ";
    const char mask[] = "xxxx     xxxx"
                        "xxxx     xxxx"
                        " xxxx   xxxx "
                        "  xxxx xxxx  "
                        "   xxxxxxx   "
                        "    xxxxx    "
                        "   xxxxxxx   "
                        "  xxxx xxxx  "
                        " xxxx   xxxx "
                        "xxxx     xxxx"
                        "xxxx     xxxx";

    rfbCursorPtr c = rfbMakeXCursor(width, height, (char *)cursor, (char *)mask);
    if (!c)
        return;

    c->xhot = width / 2;
    c->yhot = height / 2;
    rfbSetCursor(screen, c);
}

NS_INLINE void setupAlphaCursor(rfbScreenInfoPtr screen, int mode) {
    int i, j;
    rfbCursorPtr c = screen ? screen->cursor : NULL;
    if (!c)
        return;

    int maskStride = (c->width + 7) / 8;

    if (c->alphaSource) {
        free(c->alphaSource);
        c->alphaSource = NULL;
    }
    if (mode == 0)
        return;

    c->alphaSource = (unsigned char *)malloc((size_t)c->width * (size_t)c->height);
    if (!c->alphaSource)
        return;

    for (j = 0; j < c->height; j++) {
        for (i = 0; i < c->width; i++) {
            unsigned char value = (unsigned char)(0x100 * i / c->width);
            rfbBool masked = (c->mask[(i / 8) + maskStride * j] << (i & 7)) & 0x80;
            c->alphaSource[i + c->width * j] = (unsigned char)(masked ? (mode == 1 ? value : 0xff - value) : 0);
        }
    }

    if (c->cleanupMask)
        free(c->mask);

    c->mask = (unsigned char *)rfbMakeMaskFromAlphaSource(c->width, c->height, c->alphaSource);
    c->cleanupMask = TRUE;
}

#pragma mark - Setups (Native)

static void prepareClipboardManager(void) {
    // server->client sync; start/stop tied to client presence
    if (gClipboardEnabled) {
        [[ClipboardManager sharedManager] setOnChange:^(NSString *_Nullable text) {
            // If we’re in suppression (coming from client->server), do nothing
            if (gClipboardSuppressSend.load(std::memory_order_relaxed) > 0)
                return;
            sendClipboardToClients(text);
        }];
    } else {
        [[ClipboardManager sharedManager] setOnChange:nil];
    }
}

static void prepareScreenCapturer(void) {
    // Apply preferred frame rate (if provided)
    if (gFpsMin > 0 || gFpsPref > 0 || gFpsMax > 0) {
        TVLog(@"Applying preferred FPS to ScreenCapturer: min=%d pref=%d max=%d", gFpsMin, gFpsPref, gFpsMax);
        [[ScreenCapturer sharedCapturer] setPreferredFrameRateWithMin:gFpsMin preferred:gFpsPref max:gFpsMax];
    }

    gFrameHandler = ^(CMSampleBufferRef _Nonnull sampleBuffer) {
        handleFramebuffer(sampleBuffer);
    };
}

static void prepareBulletinManager(void) {
    BulletinManager *mgr = [BulletinManager sharedManager];
    [mgr revokeSingleNotification];
}

static void setupGeometry(void) {
    NSDictionary *props = [[ScreenCapturer sharedCapturer] renderProperties];
    gSrcWidth = [props[(__bridge NSString *)kIOSurfaceWidth] intValue];
    gSrcHeight = [props[(__bridge NSString *)kIOSurfaceHeight] intValue];
    if (gSrcWidth <= 0 || gSrcHeight <= 0) {
        TVPrintError("Failed to get screen dimensions");
        exit(EXIT_FAILURE);
    }

    // Apply output scaling if requested, then align (width multiple of 4)
    int tmpW = (gScale > 0.0 && gScale < 1.0) ? MAX(1, (int)floor((double)gSrcWidth * gScale)) : gSrcWidth;
    int tmpH = (gScale > 0.0 && gScale < 1.0) ? MAX(1, (int)floor((double)gSrcHeight * gScale)) : gSrcHeight;
    alignDimensions(tmpW, tmpH, &gWidth, &gHeight);
    gFBSize = (size_t)gWidth * (size_t)gHeight * (size_t)gBytesPerPixel;

    // Allocate double buffers (tightly packed BGRA/ARGB32)
    gFrontBuffer = calloc(1, gFBSize);
    gBackBuffer = calloc(1, gFBSize);
    if (!gFrontBuffer || !gBackBuffer) {
        TVPrintError("Failed to allocate required frame buffers");
        exit(EXIT_FAILURE);
    }
}

#if !TARGET_IPHONE_SIMULATOR
NS_INLINE UIInterfaceOrientation makeInterfaceOrientationRotate90(UIInterfaceOrientation o) {
    switch (o) {
    case UIInterfaceOrientationPortrait:
        return UIInterfaceOrientationLandscapeLeft;
    case UIInterfaceOrientationPortraitUpsideDown:
        return UIInterfaceOrientationLandscapeRight;
    case UIInterfaceOrientationLandscapeLeft:
        return UIInterfaceOrientationPortraitUpsideDown;
    case UIInterfaceOrientationLandscapeRight:
    default:
        return UIInterfaceOrientationPortrait;
    }
}
#endif

// Map UIInterfaceOrientation to rotation quadrant (clockwise degrees/90)
NS_INLINE int rotationForOrientation(UIInterfaceOrientation o) {
#if !TARGET_IPHONE_SIMULATOR
    if (gShouldApplyOrientationFix) {
        o = makeInterfaceOrientationRotate90(o);
    }
#endif
    switch (o) {
    case UIInterfaceOrientationPortrait:
    default:
        return 0; // 0°
    case UIInterfaceOrientationPortraitUpsideDown:
        return 2; // 180°
    case UIInterfaceOrientationLandscapeLeft:
        return 1; // 90° CW
    case UIInterfaceOrientationLandscapeRight:
        return 3; // 270° CW
    }
}

static void setupOrientationObserver(void) {
    if (!gOrientationSyncEnabled)
        return;

    static FBSOrientationObserver *sObserver;
    sObserver = [[FBSOrientationObserver alloc] init];
    if (!sObserver) {
        TVPrintError("Failed to create orientation observer instance");
        exit(EXIT_FAILURE);
    }

    // Set update handler
    void (^handler)(FBSOrientationUpdate *) = ^(FBSOrientationUpdate *update) {
        if (!update)
            return;

        UIInterfaceOrientation activeOrientation = [update orientation];

        // Note: Actual framebuffer rotation will be handled in the next step.
        gRotationQuad.store(rotationForOrientation(activeOrientation), std::memory_order_relaxed);

#if DEBUG
        NSUInteger seq = [update sequenceNumber];
        NSInteger direction = [update rotationDirection];
        NSTimeInterval dur = [update duration];
        TVLog(@"Orientation update: seq=%lu dir=%ld ori=%ld dur=%.3f", seq, direction, (long)activeOrientation, dur);
#endif
    };

    [sObserver setHandler:handler];

    // Prime current orientation if available
    UIInterfaceOrientation activeOrientation = [sObserver activeInterfaceOrientation];
    gRotationQuad.store(rotationForOrientation(activeOrientation), std::memory_order_relaxed);

    TVLog(@"Orientation observer registered (initial=%ld -> rotQ=%d)", (long)activeOrientation,
          gRotationQuad.load(std::memory_order_relaxed));
}

#pragma mark - Setups (RFB)

static void setupRfbScreen(int argc, const char *argv[]) {
    int argcCopy = argc; // rfbGetScreen may modify argc/argv
    char **argvCopy = (char **)argv;
    int bitsPerSample = 8;
    gScreen = rfbGetScreen(&argcCopy, argvCopy, gWidth, gHeight, bitsPerSample, 3, gBytesPerPixel);
    if (!gScreen) {
        TVPrintError("Failed to create rfbScreenInfo with rfbGetScreen");
        exit(EXIT_FAILURE);
    }

    // BGRA (little-endian) layout
    gScreen->paddedWidthInBytes = gWidth * gBytesPerPixel;
    gScreen->serverFormat.redShift = bitsPerSample * 2;   // 16
    gScreen->serverFormat.greenShift = bitsPerSample * 1; // 8
    gScreen->serverFormat.blueShift = 0;
    gScreen->frameBuffer = (char *)gFrontBuffer;

    // Desktop name
    gScreen->desktopName = strdup([gDesktopName UTF8String]);

    // Server ports
    gScreen->port = gPort;
    gScreen->ipv6port = gPort;

    // Server bind addresses
    in_addr_t v4Addr = INADDR_ANY;
    struct in6_addr v6Addr;
    memset(&v6Addr, 0, sizeof(v6Addr));

    TVBindHostKind hostKind = tvClassifyBindHost(gBindHost, &v4Addr, &v6Addr);
    if (hostKind == kTVBindHostKindIPv4) {
        gScreen->listenInterface = v4Addr;
    } else if (hostKind == kTVBindHostKindIPv6) {
        char ifaceBuf[INET6_ADDRSTRLEN];
        const char *iface = inet_ntop(AF_INET6, &v6Addr, ifaceBuf, sizeof(ifaceBuf));
        if (!iface) {
            TVPrintError("Failed to normalize IPv6 bind host");
            exit(EXIT_FAILURE);
        }
        gScreen->listen6Interface = strdup(iface);
    } else if (hostKind == kTVBindHostKindInvalid && gBindHost) {
        TVPrintError("Invalid host address: %s", [gBindHost UTF8String]);
        exit(EXIT_FAILURE);
    } else {
        // Do nothing; default ANY
    }

    // Event handlers
    gScreen->newClientHook = newClientHook;
    gScreen->displayHook = displayHook;
    gScreen->displayFinishedHook = displayFinishedHook;
    gScreen->setDesktopSizeHook = setDesktopSizeHook;
}

static void setupRfbEventHandlers(void) {
    gScreen->ptrAddEvent = ptrAddEvent;
    gScreen->kbdAddEvent = kbdAddEvent;
    gScreen->kbdReleaseAllKeys = kbdReleaseAllKeys;
}

static rfbBool tvCheckPasswordByList(rfbClientPtr cl, const char *passwd, int len) {
    // Check if client host is blocked
    if (gBlockedHosts && cl && cl->host) {
        NSString *host = [NSString stringWithUTF8String:cl->host];
        BOOL isBlocked = NO;
        @synchronized(gBlockedHosts) {
            isBlocked = [gBlockedHosts containsObject:host];
        }
        if (isBlocked) {
            TVLog(@"Rejected connection from blocked host: %@", host);
            return FALSE; // Reject authentication
        }
    }

    rfbBool rc = rfbCheckPasswordByList(cl, passwd, len);

    TVClientState *st = tvGetClientState(cl);
    NSString *updateKey = nil;
    if (st && st->clientId8[0] != '\0') {
        updateKey = [NSString stringWithUTF8String:st->clientId8];
    }

    if (!updateKey)
        updateKey = tvGenerateClientId8(cl->sock);
    if (updateKey && gClientStates) {
        @synchronized(gClientStates) {
            NSMutableDictionary *entry = [gClientStates[updateKey] mutableCopy];
            if (entry) {
                entry[@"viewOnly"] = @(cl->viewOnly ? YES : NO);
                gClientStates[updateKey] = [entry copy];
            }
        }
    }

    // Notify subscribers about property change (debounced)
    tvCtlScheduleBroadcastChanged();

    return rc;
}

static void setupRfbClassicAuthentication(void) {
    // Enable classic VNC authentication if environment variables are provided
    const char *envPwd = getenv("TROLLVNC_PASSWORD");
    const char *envViewPwd = getenv("TROLLVNC_VIEWONLY_PASSWORD");

    int fullCount = (envPwd && *envPwd) ? 1 : 0;
    int viewCount = (envViewPwd && *envViewPwd) ? 1 : 0;
    if (fullCount + viewCount > 0) {
        // Vector size = number of passwords + 1 for NULL terminator
        int vecCount = fullCount + viewCount + 1;
        gAuthPasswdVec = (char **)calloc((size_t)vecCount, sizeof(char *));

        int idx = 0;
        if (fullCount) {
            gAuthPasswdStr = strdup(envPwd);
            gAuthPasswdVec[idx++] = gAuthPasswdStr;
        }

        if (viewCount) {
            gAuthViewOnlyPasswdStr = strdup(envViewPwd);
            gAuthPasswdVec[idx++] = gAuthViewOnlyPasswdStr;
        }

        gAuthPasswdVec[idx] = NULL; // NULL-terminated array
        gScreen->authPasswdData = (void *)gAuthPasswdVec;

        // Index of first view-only password = number of full-access passwords
        // From that index onward (1-based in description, 0-based in array) are view-only.
        gScreen->authPasswdFirstViewOnly = fullCount;
        gScreen->passwordCheck = tvCheckPasswordByList;

        TVLog(@"Classic VNC authentication enabled via env: full=%d, view-only=%d", fullCount, viewCount);
    }
}

static void setupRfbCutTextHandlers(void) {
    // client->server sync
    if (gClipboardEnabled) {
        gScreen->setXCutText = setXCutTextLatin1;
        gScreen->setXCutTextUTF8 = setXCutTextUTF8;
        TVLog(@"Clipboard: client->server handlers registered (enabled)");
    } else {
        TVLog(@"Clipboard: client->server handlers not registered (disabled)");
    }
}

static void setupRfbServerSideCursor(void) {
    if (gCursorEnabled) {
        setupXCursor(gScreen);
        setupAlphaCursor(gScreen, 0);
        TVLog(@"Cursor: XCursor + alpha mode=2 enabled");
    } else {
        TVLog(@"Cursor: disabled (default; enable with -U on)");
    }
}

static void setupRfbHttpServer(void) {
    // Built-in HTTP server settings (see rfb.h http* fields)
    gScreen->httpEnableProxyConnect = TRUE; // always allow CONNECT if HTTP is enabled
    if (gHttpPort > 0) {
        gScreen->httpPort = gHttpPort; // enable HTTP on specified port
        gScreen->http6Port = gHttpPort;
        if (gHttpDirOverride) {
            // Use override absolute path
            gScreen->httpDir = strdup(gHttpDirOverride);
            TVLog(@"HTTP server config: port=%d, dir=%s (override), proxyConnect=YES", gHttpPort, gHttpDirOverride);
        } else {
            // Compute httpDir relative to executable: ../share/trollvnc/webclients
            do {
                NSString *exe = tvExecutablePath();
                NSString *exeDir = [exe stringByDeletingLastPathComponent];
                NSString *webRel;
#ifdef THEBOOTSTRAP
                webRel = @"./webclients";
#else
                webRel = @"../share/trollvnc/webclients";
#endif
                NSString *webPath = [[exeDir stringByAppendingPathComponent:webRel] stringByStandardizingPath];
                const char *fs = [webPath fileSystemRepresentation];
                if (fs && *fs) {
                    gScreen->httpDir = strdup(fs);
                    TVLog(@"HTTP server config: port=%d, dir=%@, proxyConnect=YES", gHttpPort, webPath);
                }
            } while (0);
        }
    } else {
        gScreen->httpPort = 0;   // disabled
        gScreen->httpDir = NULL; // do not set dir to avoid default startup
    }

    // SSL certificate and key (optional)
    if (gSslCertPath && *gSslCertPath) {
        gScreen->sslcertfile = strdup(gSslCertPath);
    }
    if (gSslKeyPath && *gSslKeyPath) {
        gScreen->sslkeyfile = strdup(gSslKeyPath);
    }
}

static BOOL gFileTransferRegistered = NO;

static void setupRfbFileTransferExtension(void) {
    if (!gFileTransferEnabled) {
        return;
    }

    TVLog(@"TightVNC 1.x file transfer extension registered");
    rfbRegisterTightVNCFileTransferExtension();

    gFileTransferRegistered = YES;
}

#pragma mark - Setups (Event Model)

static const long cSelectTimeout = 1e4; // 10 ms

// Background event thread for reverse-connection mode
static pthread_t gRfbEventThread = 0;
static std::atomic<int> gRfbEventThreadRunning(0);

static void *tvRfbEventThreadMain(void *arg) {
    (void)arg;
    for (;;) {
        if (!gRfbEventThreadRunning.load(std::memory_order_relaxed))
            break;
        if (!gScreen)
            break;
        rfbProcessEvents(gScreen, cSelectTimeout);
        if (!rfbIsActive(gScreen))
            break;
    }
    CFRunLoopStop(CFRunLoopGetMain());
    gRfbEventThreadRunning.store(0, std::memory_order_relaxed);
    return NULL;
}

static void tvStartRfbEventThread(void) {
    if (gRfbEventThreadRunning.exchange(1, std::memory_order_acq_rel))
        return;
    int rc = pthread_create(&gRfbEventThread, NULL, tvRfbEventThreadMain, NULL);
    if (rc != 0) {
        gRfbEventThreadRunning.store(0, std::memory_order_relaxed);
        TVPrintError("Failed to create VNC event thread (rc=%d)", rc);
        exit(EXIT_FAILURE);
    }
}

static void tvStopRfbEventThread(void) {
    if (!gRfbEventThreadRunning.exchange(0, std::memory_order_acq_rel))
        return;
    if (gRfbEventThread) {
        if (!pthread_equal(gRfbEventThread, pthread_self()))
            pthread_join(gRfbEventThread, NULL);
        gRfbEventThread = 0;
    }
}

static void initializeAndRunRfbServer(void) {
    rfbInitServer(gScreen);
    TVLog(@"VNC server initialized on port %d, %dx%d, name '%@'", gPort, gWidth, gHeight, gDesktopName);

    if (isRepeaterEnabled()) {
        static CFTimeInterval sRetryInterval = 0.0;
        const char *envRetryInterval = getenv("TROLLVNC_REPEATER_RETRY_INTERVAL");
        if (envRetryInterval) {
            sRetryInterval = atof(envRetryInterval);
        }

        static rfbClientPtr sClient = NULL;
        if (gRepeaterMode == 2) {
            TVLog(@"VNC server running in repeater mode");
            static NSString *sRepeaterId = [NSString stringWithFormat:@"%d", gRepeaterId];
            const char *repeaterId = [sRepeaterId UTF8String];
            sClient = rfbUltraVNCRepeaterMode2Connection(gScreen, gRepeaterHost, gRepeaterPort, repeaterId);
        } else {
            TVLog(@"VNC server running in viewer mode");
            sClient = rfbReverseConnection(gScreen, gRepeaterHost, gRepeaterPort);
        }

        if (!sClient) {
            TVPrintError("Failed to establish reverse connection to %s", gRepeaterHost);
            if (sRetryInterval > 0)
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, sRetryInterval, false);
            exit(EXIT_FAILURE);
        }

        TVClientState *st = tvGetClientState(sClient);
        if (st) {
            st->isRepeaterClient = YES;
        }

        TVLog(@"Reverse connection established to %s", gRepeaterHost);

        // Start background event thread to pump events while in reverse mode
        tvStartRfbEventThread();
    } else {
        // Run VNC in background thread
        rfbRunEventLoop(gScreen, cSelectTimeout, TRUE);
    }

    // Start Bonjour advertisement after server is ready
    startBonjour();
}

static void handleSignal(int signum) {
    (void)signum;
    TVLog(@"Signal %d received", signum);

    // Best-effort: stop runloop to unwind main and allow cleanup.
    CFRunLoopStop(CFRunLoopGetMain());
}

static void installSignalHandlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handleSignal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void installTerminationHandlers(void) {
    atexit_b(^(void) {
#if !TARGET_OS_SIMULATOR
        if (gRestoreAssist) {
            gRestoreAssist = NO;
            [PSAssistiveTouchSettingsDetail setEnabled:NO];
        }
#endif
    });
}

#pragma mark - Logging

BOOL tvncLoggingEnabled = YES;
BOOL tvncVerboseLoggingEnabled = NO;

#define LOCK(mutex) pthread_mutex_lock(&(mutex))
#define UNLOCK(mutex) pthread_mutex_unlock(&(mutex))

static MUTEX(logMutex);
static int logMutex_initialized = 0;

static void rfbCustomLog(const char *format, ...) {
    va_list args;
    char buf[256];
    time_t log_clock;

    if (!tvncLoggingEnabled)
        return;

    if (!logMutex_initialized) {
        INIT_MUTEX(logMutex);
        logMutex_initialized = 1;
    }

    LOCK(logMutex);
    va_start(args, format);

    time(&log_clock);
    strftime(buf, 255, "%Y-%m-%d %X ", localtime(&log_clock));
    fprintf(stderr, "%s", buf);

    /* If format ends with a \n, replace with \r\n */
    const char *fmt_to_use = format;
    char *fmt_copy = NULL;
    if (format) {
        size_t flen = strlen(format);
        if (flen > 0 && format[flen - 1] == '\n') {
            fmt_copy = (char *)malloc(flen + 2);
            if (fmt_copy) {
                memcpy(fmt_copy, format, flen - 1);
                fmt_copy[flen - 1] = '\r';
                fmt_copy[flen] = '\n';
                fmt_copy[flen + 1] = '\0';
                fmt_to_use = fmt_copy;
            }
        }
    }

    vfprintf(stderr, fmt_to_use, args);
    fflush(stderr);

    if (fmt_copy)
        free(fmt_copy);

    va_end(args);
    UNLOCK(logMutex);
}

static void setupRfbLogging(void) { rfbLog = rfbErr = rfbCustomLog; }

#pragma mark - Main Procedure

#define REQUIRED_UID 501
#define REQUIRED_GID 501

static void dropPrivileges(void) {
    if (isatty(STDIN_FILENO)) {
        return;
    }

    int rc;
    if (getuid() != REQUIRED_UID) {
        rc = setuid(REQUIRED_UID);
        if (rc != 0) {
            TVPrintError("Failed to set uid to %d: %d", REQUIRED_UID, rc);
            exit(EXIT_FAILURE);
        }
    }

    if (getgid() != REQUIRED_GID) {
        rc = setgid(REQUIRED_GID);
        if (rc != 0) {
            TVPrintError("Failed to set gid to %d: %d", REQUIRED_GID, rc);
            // exit(EXIT_FAILURE);
        }
    }
}

static void cleanupAndExit(int code) {
    // Stop auto discovery
    stopBonjour();

    // Clear all user notifications
    [[BulletinManager sharedManager] revokeAllNotifications];

    // Stop control socket if any
    tvStopControlSocket();

    // Stop event thread if running
    tvStopRfbEventThread();

    if (gFileTransferRegistered) {
        rfbUnregisterTightVNCFileTransferExtension();
    }

    if (gScreen) {
        rfbShutdownServer(gScreen, YES);
        rfbScreenCleanup(gScreen);
        gScreen = NULL;
    }

    // There’s no need to free other resources because we’re going to exit the process. Yay!
    exit(code);
}

#ifdef THEBOOTSTRAP
#define SINGLETON_PARENT_NAME "trollvncmanager"
#define SINGLETON_MARKER_PATH "/var/mobile/Library/Caches/com.82flex.trollvnc.server.pid"

static void monitorParentProcess(void) {
    if (isatty(STDIN_FILENO)) {
        return;
    }

    static pid_t ppid = getppid();
    if (ppid == 1) {
        return;
    }

    static dispatch_source_t source =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, ppid, DISPATCH_PROC_EXIT | DISPATCH_PROC_SIGNAL,
                               dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0));

    dispatch_source_set_event_handler(source, ^{
        if (dispatch_source_get_data(source) & DISPATCH_PROC_EXIT) {
            dispatch_source_cancel(source);
            TVPrintError("Parent process %d exited", ppid);
            exit(EXIT_SUCCESS);
        } else if (kill(ppid, 0) == -1 && errno == ESRCH) {
            dispatch_source_cancel(source);
            TVPrintError("Parent process %d is gone", ppid);
            exit(EXIT_SUCCESS);
        }
    });

    dispatch_resume(source);
}

static void monitorSelfAndRestartIfVnodeDeleted(const char *executable) {
    int myHandle = open(executable, O_EVTONLY);
    if (myHandle <= 0) {
        return;
    }

    static unsigned long monitorMask = DISPATCH_VNODE_DELETE;
    static dispatch_source_t monitorSource;
    monitorSource =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, myHandle, monitorMask, dispatch_get_main_queue());

    dispatch_source_set_event_handler(monitorSource, ^{
        unsigned long flags = dispatch_source_get_data(monitorSource);
        if (flags & DISPATCH_VNODE_DELETE) {
            dispatch_source_cancel(monitorSource);
            exit(EXIT_SUCCESS);
        }
    });

    dispatch_resume(monitorSource);
}

static void ensureSingleton(const char *argv[]) {
    if (isatty(STDIN_FILENO)) {
        return;
    }

    if (!argv || !argv[0] || argv[0][0] != '/') {
        return;
    }

    monitorSelfAndRestartIfVnodeDeleted(argv[0]);

    NSString *markerPath = @SINGLETON_MARKER_PATH;
    const char *cMarkerPath = [markerPath fileSystemRepresentation];

    // Open file for read/write, create if doesn't exist
    static int lockFD = open(cMarkerPath, O_RDWR | O_CREAT, 0644);
    if (lockFD == -1) {
        TVPrintError("Failed to open lock file: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Try to acquire an exclusive lock
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; // Lock entire file

    if (fcntl(lockFD, F_SETLK, &fl) == -1) {
        // Lock already held by another process
        TVPrintError("Another instance is already running");
        close(lockFD);
        exit(EXIT_FAILURE);
    }

    // Truncate the file to clear any previous content
    if (ftruncate(lockFD, 0) == -1) {
        TVPrintError("Failed to truncate lock file: %s", strerror(errno));
        // Continue anyway
    }

    // Write PID to file
    pid_t pid = getpid();
    char pidStr[16];
    int len = snprintf(pidStr, sizeof(pidStr), "%d\n", pid);
    if (write(lockFD, pidStr, len) != len) {
        TVPrintError("Failed to write PID to lock file: %s", strerror(errno));
        // Continue anyway
    }

    // Keep the file descriptor open to maintain the lock
    // It will be automatically closed when the process exits
    fchown(lockFD, 501, 501);
}
#endif

int main(int argc, const char *argv[]) {

    /* Drop privileges: this program should run as mobile */
    dropPrivileges();

    @autoreleasepool {
        parseCLI(argc, argv);

#ifdef THEBOOTSTRAP
        monitorParentProcess();
        ensureSingleton(argv);
#endif
    }

    /* Do nothing but keep the runloop alive */
    if (!gEnabled) {
        CFRunLoopRun();
        return EXIT_SUCCESS;
    }

    @autoreleasepool {
        setupGeometry();
        setupOrientationObserver();

        setupRfbLogging();
        setupRfbScreen(argc, argv);
        setupRfbEventHandlers();
        setupRfbClassicAuthentication();
        setupRfbCutTextHandlers();
        setupRfbServerSideCursor();
        setupRfbHttpServer();
        setupRfbFileTransferExtension();

        prepareBulletinManager();
        prepareClipboardManager();
        prepareScreenCapturer();

        initializeTilingOrReset();
        initializeAndRunRfbServer();

        installSignalHandlers();
        installTerminationHandlers();

        tvStartControlSocketIfNeeded();
    }

    CFRunLoopRun();
    cleanupAndExit(EXIT_SUCCESS);

    return EXIT_SUCCESS;
}