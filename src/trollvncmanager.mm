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

#import <Foundation/Foundation.h>

#import <arpa/inet.h>
#import <fcntl.h>
#import <netinet/in.h>
#import <notify.h>
#import <spawn.h>
#import <stdlib.h>
#import <sys/proc_info.h>
#import <sys/socket.h>
#import <unistd.h>

#import "Control.h"
#import "Logging.h"
#import "TRWatchDog.h"
#import "libproc.h"

#define SINGLETON_MARKER_PATH "/var/mobile/Library/Caches/com.82flex.trollvnc.manager.pid"

BOOL tvncLoggingEnabled = YES;
BOOL tvncVerboseLoggingEnabled = NO;

static TRWatchDog *gWatchDog = nil;

static void mSignalAction(int signal, struct __siginfo *info, void *context) {
    if (signal == SIGCHLD) {
        int unused;
        waitpid(info->si_pid, &unused, WNOHANG);
    }
}

static void mSignalHandler(int signal) {
    fprintf(stderr, "signal %d received\n", signal);

    /* Terminate itself */
    if (signal == SIGHUP || signal == SIGINT) {
        CFRunLoopStop(CFRunLoopGetMain());
    } else if (signal == SIGTERM) {
        exit((EXIT_FAILURE << 7) | signal);
    }
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

// Open a local IPv4 TCP listener on 127.0.0.1:port that accepts and
// immediately closes connections (no response). This lets clients detect
// the service by a successful connect without any protocol exchange.
static void openLocalDummyService(uint16_t port) {
    static int sListenFD = -1;
    static dispatch_source_t sAcceptSource = nil;
    if (sListenFD != -1 || sAcceptSource) {
        return; // already set up
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[dummy-listener] socket() failed: %s\n", strerror(errno));
        return;
    }

    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    // Non-blocking for accept loop
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[dummy-listener] bind(127.0.0.1:%u) failed: %s\n", (unsigned)port, strerror(errno));
        close(fd);
        return;
    }

    if (listen(fd, SOMAXCONN) < 0) {
        fprintf(stderr, "[dummy-listener] listen() failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    sListenFD = fd;
    sAcceptSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, dispatch_get_main_queue());
    if (!sAcceptSource) {
        close(fd);
        sListenFD = -1;
        return;
    }

    dispatch_source_set_event_handler(sAcceptSource, ^{
        while (1) {
            struct sockaddr_storage clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int cfd = accept(fd, (struct sockaddr *)&clientAddr, &clientLen);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    break;
                }
                // Unexpected error; break to avoid busy loop
                break;
            }
            // Immediately close; no response needed
            close(cfd);
        }
    });

    dispatch_source_set_cancel_handler(sAcceptSource, ^{
        if (sListenFD != -1) {
            close(sListenFD);
            sListenFD = -1;
        }
    });

    dispatch_resume(sAcceptSource);
    fprintf(stderr, "[dummy-listener] listening on 127.0.0.1:%u\n", (unsigned)port);
}

int main(int argc, const char *argv[]) {
    if (!argv || !argv[0] || argv[0][0] != '/') {
        fprintf(stderr, "This program must be run from an absolute path\n");
        return EXIT_FAILURE;
    }

    /* Singleton */
    monitorSelfAndRestartIfVnodeDeleted(argv[0]);

    NSString *markerPath = @SINGLETON_MARKER_PATH;
    const char *cMarkerPath = [markerPath fileSystemRepresentation];

    // Open file for read/write, create if doesn't exist
    static int lockFD = open(cMarkerPath, O_RDWR | O_CREAT, 0644);
    if (lockFD == -1) {
        fprintf(stderr, "Failed to open lock file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Try to acquire an exclusive lock
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; // Lock entire file

    if (fcntl(lockFD, F_SETLK, &fl) == -1) {
        // Lock already held by another process
        fprintf(stderr, "Another instance is already running\n");
        close(lockFD);
        return EXIT_FAILURE;
    }

    // Truncate the file to clear any previous content
    if (ftruncate(lockFD, 0) == -1) {
        fprintf(stderr, "Failed to truncate lock file: %s\n", strerror(errno));
        // Continue anyway
    }

    // Write PID to file
    pid_t pid = getpid();
    char pidStr[16];
    int len = snprintf(pidStr, sizeof(pidStr), "%d\n", pid);
    if (write(lockFD, pidStr, len) != len) {
        fprintf(stderr, "Failed to write PID to lock file: %s\n", strerror(errno));
        // Continue anyway
    }

    // Keep the file descriptor open to maintain the lock
    // It will be automatically closed when the process exits
    fchown(lockFD, 501, 501);

    @autoreleasepool {
        NSString *executablePath = [NSString stringWithUTF8String:argv[0]];
        executablePath = [executablePath stringByDeletingLastPathComponent];
        executablePath = [executablePath stringByAppendingPathComponent:@"trollvncserver"];

        gWatchDog = [[TRWatchDog alloc] init];

        [gWatchDog setLabel:@"TrollVNC-Server"];
        [gWatchDog setProgramArguments:@[
            executablePath,
            @"-daemon",
        ]];

        NSMutableDictionary *mEnvs = [[[NSProcessInfo processInfo] environment] mutableCopy];
        [mEnvs addEntriesFromDictionary:@{
            @"TROLLVNC_REPEATER_RETRY_INTERVAL" : @"30.0",
        }];

        [gWatchDog setEnvironmentVariables:mEnvs];
        [gWatchDog setWorkingDirectory:[[NSFileManager defaultManager] currentDirectoryPath]];

        NSString *rootPath = executablePath;
        do {
            if ([rootPath hasSuffix:@"/procursus"] || [rootPath hasSuffix:@"/var/jb"] ||
                [[rootPath lastPathComponent] hasPrefix:@".jbroot-"]) {
                // Found the jailbreak root
                break;
            }
            if ([rootPath hasPrefix:@"/private/preboot/"] && [rootPath hasSuffix:@"/jb"]) {
                // Found the jailbreak root (NathanLR)
                break;
            }
            if ([rootPath isEqualToString:@"/"] || !rootPath.length) {
                // Reached the root without finding jailbreak root
                break;
            }
            rootPath = [rootPath stringByDeletingLastPathComponent];
        } while (YES);

        NSString *stdoutPath = [rootPath stringByAppendingPathComponent:@"tmp/trollvnc-stdout.log"];
        NSString *stderrPath = [rootPath stringByAppendingPathComponent:@"tmp/trollvnc-stderr.log"];

        [gWatchDog setStandardOutputPath:stdoutPath];
        [gWatchDog setStandardErrorPath:stderrPath];

        BOOL isOwnedByRoot = NO;
        struct stat sb;
        if (stat([executablePath fileSystemRepresentation], &sb) == 0) {
            isOwnedByRoot = (sb.st_uid == 0);
        }

        if (isOwnedByRoot) {
            /* If the executable is owned by root, run as root */
            /* The privilege will be dropped by the child process itself */
            [gWatchDog setUserName:@"root"];
            [gWatchDog setGroupName:@"wheel"];
        } else {
            [gWatchDog setUserName:@"mobile"];
            [gWatchDog setGroupName:@"mobile"];
        }

        [gWatchDog setExitTimeOut:3.0];
        [gWatchDog setThrottleInterval:5.0];
        [gWatchDog setKeepAlive:@YES];

        NSError *argError = nil;
        BOOL validated = [gWatchDog validateConfigurationWithError:&argError];
        if (!validated) {
            fprintf(stderr, "Invalid configuration: %s\n", [[argError localizedDescription] UTF8String]);
            return EXIT_FAILURE;
        }

        BOOL started = [gWatchDog start];
        if (!started) {
            fprintf(stderr, "Failed to start watchdog\n");
            return EXIT_FAILURE;
        }
    }

    {
        // handle SIGCHLD signal
        struct sigaction act, oldact;
        act.sa_sigaction = &mSignalAction;
        act.sa_flags = SA_SIGINFO;
        sigaction(SIGCHLD, &act, &oldact);
    }
    {
        // handle SIGHUP signal
        struct sigaction act, oldact;
        act.sa_handler = &mSignalHandler;
        sigaction(SIGHUP, &act, &oldact);
    }
    {
        // handle SIGINT signal
        struct sigaction act, oldact;
        act.sa_handler = &mSignalHandler;
        sigaction(SIGINT, &act, &oldact);
    }
    {
        // handle SIGTERM signal
        struct sigaction act, oldact;
        act.sa_handler = &mSignalHandler;
        sigaction(SIGTERM, &act, &oldact);
    }

    // Open a passive local probe port for clients to detect availability.
    // IPv4 127.0.0.1:46751, no response; accept and close.
    openLocalDummyService(kTvAlivePort);

    CFRunLoopRun();
    @autoreleasepool {
        pid_t child = [gWatchDog processIdentifier];
        [gWatchDog stop];
        gWatchDog = nil;

        // Wait for the child process to exit
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5.0];
        while (child > 1 && kill(child, 0) == 0 && [deadline timeIntervalSinceNow] > 0) {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1e-3, true);
        }
    }

    return EXIT_SUCCESS;
}
