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

#import "TVNCClientListController.h"
#import "TVNCClientCell.h"

#import <UIKit/UIKit.h>
#import <arpa/inet.h>
#import <errno.h>
#import <netinet/in.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

#import "Control.h"

#pragma mark - Networking

// Placeholder item id used when there are no clients
static NSString *const kTVNCEmptyItemId = @"__empty__";

static inline BOOL TVNCIsEmptyItemId(NSString *_Nullable itemId) {
    return itemId != nil && [itemId isEqualToString:kTVNCEmptyItemId];
}

static NSData *TVNCReadAll(int fd, double timeoutSec) {
    NSMutableData *md = [NSMutableData data];
    struct timeval tv;
    tv.tv_sec = (int)timeoutSec;
    tv.tv_usec = (int)((timeoutSec - tv.tv_sec) * 1e6);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t buf[2048];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        [md appendBytes:buf length:(NSUInteger)n];
        if (n < (ssize_t)sizeof(buf))
            break;
    }
    return md;
}

static int TVNCSendLine(int fd, NSString *line) {
    NSString *ln = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *d = [ln dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *p = d.bytes;
    size_t left = d.length;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        p += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}

static int TVNCConnect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kTvDefaultCtlPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

#pragma mark - Private Interface

@interface TVNCClientListController ()

@property(nonatomic, strong) UIBarButtonItem *dismissItem;
@property(nonatomic, strong) UIBarButtonItem *disconnectItem;

@property(nonatomic, strong) UITableViewDiffableDataSource<NSString *, NSString *> *dataSource; // section -> itemId
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *clientLookup;     // id -> dict

// Subscription (long-lived connection)
@property(nonatomic, assign) int subFd;
@property(nonatomic, strong) dispatch_source_t subReadSource;

@end

#pragma mark - Implementation

@implementation TVNCClientListController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.title = NSLocalizedStringFromTableInBundle(@"Clients", @"Localizable", self.bundle, nil);

    UIRefreshControl *refreshControl = [UIRefreshControl new];
    [refreshControl addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = refreshControl;

    self.navigationItem.leftBarButtonItem = self.disconnectItem;
    self.navigationItem.rightBarButtonItem = self.dismissItem;

    // Diffable data source
    self.clientLookup = [NSMutableDictionary new];
    __weak typeof(self) weakSelf = self;
    self.dataSource = [[UITableViewDiffableDataSource alloc]
        initWithTableView:self.tableView
             cellProvider:^UITableViewCell *_Nullable(UITableView *tableView, NSIndexPath *indexPath,
                                                      NSString *identifier) {
                 return [weakSelf cellForTableView:tableView indexPath:indexPath itemId:identifier];
             }];

    // Initial empty snapshot with one section
    NSDiffableDataSourceSnapshot<NSString *, NSString *> *empty = [NSDiffableDataSourceSnapshot new];
    [empty appendSectionsWithIdentifiers:@[ @"main" ]];
    [self.dataSource applySnapshot:empty animatingDifferences:NO];

    [self refresh];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self startSubscriptionIfNeeded];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self stopSubscription];
}

- (void)dealloc {
    [self stopSubscription];
}

#pragma mark - Getters

- (UIBarButtonItem *)dismissItem {
    if (!_dismissItem) {
        _dismissItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemClose
                                                                     target:self
                                                                     action:@selector(dismiss)];
    }
    return _dismissItem;
}

- (UIBarButtonItem *)disconnectItem {
    if (!_disconnectItem) {
        NSString *title = NSLocalizedStringFromTableInBundle(@"Disconnect All", @"Localizable", self.bundle, nil);
        _disconnectItem = [[UIBarButtonItem alloc] initWithTitle:title
                                                           style:UIBarButtonItemStylePlain
                                                          target:self
                                                          action:@selector(disconnectAll)];
        _disconnectItem.tintColor = self.primaryColor;
        _disconnectItem.enabled = NO;
    }
    return _disconnectItem;
}

#pragma mark - Subscription (Plan B)

- (void)startSubscriptionIfNeeded {
    if (self.subFd > 0 || self.subReadSource)
        return;

    int fd = TVNCConnect();
    if (fd < 0)
        return;

    if (TVNCSendLine(fd, @"subscribe on") < 0) {
        close(fd);
        return;
    }

    // Best-effort read initial OK
    (void)TVNCReadAll(fd, 0.5);

    self.subFd = fd;

    dispatch_queue_t q = dispatch_get_main_queue();
    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, q);
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(src, ^{
        [weakSelf onSubscriptionReadable];
    });

    dispatch_source_set_cancel_handler(src, ^{
        if (weakSelf.subFd > 0) {
            close(weakSelf.subFd);
            weakSelf.subFd = 0;
        }
    });

    self.subReadSource = src;
    dispatch_resume(src);
}

- (void)stopSubscription {
    if (self.subReadSource) {
        dispatch_source_cancel(self.subReadSource);
        self.subReadSource = nil;
    }
    if (self.subFd > 0) {
        // Best-effort to inform server (non-fatal if it fails)
        (void)TVNCSendLine(self.subFd, @"subscribe off");
        close(self.subFd);
        self.subFd = 0;
    }
}

#pragma mark - Actions

- (void)dismiss {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)refresh {
    [self reloadDataFromServer];
}

// Removed index-based disconnect; use -disconnectClientWithId:block: instead.

- (void)disconnectClientWithId:(NSString *)cid block:(BOOL)shouldBlock {
    if (cid.length == 0)
        return;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int fd = TVNCConnect();
        if (fd >= 0) {
            NSString *cmd = shouldBlock ? @"block" : @"disconnect";
            TVNCSendLine(fd, [NSString stringWithFormat:@"%@ %@", cmd, cid]);
            (void)TVNCReadAll(fd, 2.0);
            close(fd);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self refresh];
        });
    });
}

- (void)disconnectAll {
    [self.disconnectItem setEnabled:NO];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int fd = TVNCConnect();
        if (fd >= 0) {
            TVNCSendLine(fd, @"disconnect ALL");
            (void)TVNCReadAll(fd, 2.0);
            close(fd);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self refresh];
        });
    });
}

#pragma mark - Helpers (Cells)

- (UITableViewCell *)cellForTableView:(UITableView *)tableView
                            indexPath:(NSIndexPath *)indexPath
                               itemId:(NSString *)identifier {
    if (TVNCIsEmptyItemId(identifier)) {
        return [self dequeuePlaceholderCellForTableView:tableView];
    }
    return [self dequeueClientCellForTableView:tableView itemId:identifier];
}

- (UITableViewCell *)dequeuePlaceholderCellForTableView:(UITableView *)tableView {
    static NSString *const kEmptyReuse = @"TVNCEmptyCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kEmptyReuse];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:kEmptyReuse];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = [UIColor secondaryLabelColor];
        cell.textLabel.numberOfLines = 0;
    }
    cell.textLabel.text = NSLocalizedStringFromTableInBundle(@"No clients connected", @"Localizable", self.bundle, nil);
    return cell;
}

- (UITableViewCell *)dequeueClientCellForTableView:(UITableView *)tableView itemId:(NSString *)identifier {
    TVNCClientCell *cell = (TVNCClientCell *)[tableView dequeueReusableCellWithIdentifier:@"TVNCClientCell"];
    if (!cell) {
        cell = [[TVNCClientCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"TVNCClientCell"];
        cell.bundle = self.bundle;
    }

    NSDictionary *c = self.clientLookup[identifier] ?: @{};
    NSString *cid = c[@"id"] ?: identifier ?: @"";
    NSString *host = c[@"host"] ?: @"";
    BOOL vo = [[c objectForKey:@"viewOnly"] boolValue] || [[c objectForKey:@"viewOnly"] isEqual:@"1"];
    double dur = [[c objectForKey:@"durationSec"] doubleValue];

    static NSRelativeDateTimeFormatter *sFmt;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sFmt = [NSRelativeDateTimeFormatter new];
        sFmt.unitsStyle = NSRelativeDateTimeFormatterUnitsStyleFull;
    });

    NSString *rel = [sFmt localizedStringFromTimeInterval:-dur];
    NSString *subtitle = [NSString
        stringWithFormat:NSLocalizedStringFromTableInBundle(@"Connected %@", @"Localizable", self.bundle, nil),
                         rel ?: @"-"];

    [cell configureWithId:cid host:host viewOnly:vo subtitle:subtitle primaryColor:self.primaryColor];
    cell.accessoryType = UITableViewCellAccessoryNone;
    return cell;
}

#pragma mark - Helpers (Networking)

- (NSArray<NSDictionary *> *)parseTSV:(NSString *)tsv {
    if (tsv.length == 0)
        return @[];
    NSArray<NSString *> *lines = [tsv componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    NSMutableArray<NSDictionary *> *rows =
        [NSMutableArray arrayWithCapacity:MAX((NSInteger)0, (NSInteger)lines.count - 1)];
    BOOL first = YES;
    for (NSString *ln in lines) {
        if (ln.length == 0)
            continue;
        if (first) {
            first = NO;
            continue;
        } // skip header
        NSArray *cols = [ln componentsSeparatedByString:@"\t"];
        if (cols.count < 5)
            continue;
        [rows addObject:@{
            @"id" : cols[0],
            @"host" : cols[1],
            @"viewOnly" : cols[2],
            @"connectedAt" : cols[3],
            @"durationSec" : cols[4]
        }];
    }
    return rows;
}

- (void)applyRows:(NSArray<NSDictionary *> *)rows {
    [self.clientLookup removeAllObjects];

    NSMutableArray<NSString *> *ids = [NSMutableArray arrayWithCapacity:rows.count];
    for (NSDictionary *item in rows) {
        NSString *cid = item[@"id"] ?: @"";
        if (!cid.length)
            continue;
        self.clientLookup[cid] = item;
        [ids addObject:cid];
    }

    NSDiffableDataSourceSnapshot<NSString *, NSString *> *snap = [NSDiffableDataSourceSnapshot new];
    [snap appendSectionsWithIdentifiers:@[ @"main" ]];
    if (ids.count == 0) {
        [snap appendItemsWithIdentifiers:@[ kTVNCEmptyItemId ] intoSectionWithIdentifier:@"main"];
    } else {
        [snap appendItemsWithIdentifiers:ids intoSectionWithIdentifier:@"main"];
        [snap reloadItemsWithIdentifiers:ids]; // force reconfigure for content changes
    }

    [self.dataSource applySnapshot:snap animatingDifferences:YES];
    [self.disconnectItem setEnabled:(ids.count > 0)];
}

- (void)reloadDataFromServer {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int fd = TVNCConnect();
        if (fd < 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.refreshControl endRefreshing];
                [self applyRows:@[]];
            });
            return;
        }

        TVNCSendLine(fd, @"list");
        NSData *data = TVNCReadAll(fd, 2.0);
        close(fd);

        NSString *tsv = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
        NSArray<NSDictionary *> *rows = [self parseTSV:tsv];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.refreshControl endRefreshing];
            [self applyRows:rows];
        });
    });
}

- (void)onSubscriptionReadable {
    int fd = self.subFd;
    if (fd <= 0) {
        return;
    }
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        [self stopSubscription];
        return;
    }
    buf[n] = '\0';
    // Any line containing "changed" triggers a refresh
    if (memmem(buf, (size_t)n, "changed", 7) != NULL) {
        [self refresh];
    }
}

#pragma mark - Table

// Diffable data source drives cells; no need to implement UITableViewDataSource methods here.
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tableView
    trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath {

    NSString *itemId = [self.dataSource itemIdentifierForIndexPath:indexPath];
    if ([itemId isEqualToString:kTVNCEmptyItemId])
        return nil;

    __weak typeof(self) weakSelf = self;

    UIContextualAction *block = [UIContextualAction
        contextualActionWithStyle:UIContextualActionStyleDestructive
                            title:NSLocalizedStringFromTableInBundle(@"Block", @"Localizable", self.bundle, nil)
                          handler:^(__kindof UIContextualAction *action, __kindof UIView *sourceView,
                                    void (^completionHandler)(BOOL)) {
                              NSString *cid = [weakSelf.dataSource itemIdentifierForIndexPath:indexPath] ?: @"";
                              [weakSelf disconnectClientWithId:cid block:YES];
                              if (completionHandler)
                                  completionHandler(YES);
                          }];

    UIContextualAction *kick = [UIContextualAction
        contextualActionWithStyle:UIContextualActionStyleNormal
                            title:NSLocalizedStringFromTableInBundle(@"Disconnect", @"Localizable", self.bundle, nil)
                          handler:^(__kindof UIContextualAction *action, __kindof UIView *sourceView,
                                    void (^completionHandler)(BOOL)) {
                              NSString *cid = [weakSelf.dataSource itemIdentifierForIndexPath:indexPath] ?: @"";
                              [weakSelf disconnectClientWithId:cid block:NO];
                              if (completionHandler)
                                  completionHandler(YES);
                          }];

    UISwipeActionsConfiguration *config = [UISwipeActionsConfiguration configurationWithActions:@[ block, kick ]];
    config.performsFirstActionWithFullSwipe = NO;
    return config;
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    NSString *itemId = [self.dataSource itemIdentifierForIndexPath:indexPath];
    if ([itemId isEqualToString:kTVNCEmptyItemId])
        return NO;
    return YES;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
}

// iOS 14 min: Provide long-press context menu with copy actions
- (UIContextMenuConfiguration *)tableView:(UITableView *)tableView
    contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
                                        point:(CGPoint)point {
    NSString *cid = [self.dataSource itemIdentifierForIndexPath:indexPath];
    if ([cid isEqualToString:kTVNCEmptyItemId])
        return nil;
    if (cid.length == 0)
        return nil;

    NSString *host = self.clientLookup[cid][@"host"] ?: @"";
    return [UIContextMenuConfiguration
        configurationWithIdentifier:nil
                    previewProvider:nil
                     actionProvider:^UIMenu *_Nullable(NSArray<UIMenuElement *> *_Nonnull suggestedActions) {
                         UIAction *copyId = [UIAction
                             actionWithTitle:NSLocalizedStringFromTableInBundle(@"Copy ID", @"Localizable", self.bundle,
                                                                                nil)
                                       image:[UIImage systemImageNamed:@"doc.on.doc"]
                                  identifier:nil
                                     handler:^(__kindof UIAction *_Nonnull action) {
                                         [UIPasteboard generalPasteboard].string = cid;
                                         UINotificationFeedbackGenerator *gen = [UINotificationFeedbackGenerator new];
                                         [gen notificationOccurred:UINotificationFeedbackTypeSuccess];
                                     }];
                         UIAction *copyHost = [UIAction
                             actionWithTitle:NSLocalizedStringFromTableInBundle(@"Copy Host", @"Localizable",
                                                                                self.bundle, nil)
                                       image:[UIImage systemImageNamed:@"globe"]
                                  identifier:nil
                                     handler:^(__kindof UIAction *_Nonnull action) {
                                         [UIPasteboard generalPasteboard].string = host;
                                         UINotificationFeedbackGenerator *gen = [UINotificationFeedbackGenerator new];
                                         [gen notificationOccurred:UINotificationFeedbackTypeSuccess];
                                     }];
                         UIAction *disconnect = [UIAction
                             actionWithTitle:NSLocalizedStringFromTableInBundle(@"Disconnect Client", @"Localizable",
                                                                                self.bundle, nil)
                                       image:[UIImage systemImageNamed:@"xmark.circle"]
                                  identifier:nil
                                     handler:^(__kindof UIAction *_Nonnull action) {
                                         [self disconnectClientWithId:cid block:NO];
                                     }];
                         disconnect.attributes = UIMenuElementAttributesDestructive;

                         UIAction *block = [UIAction
                             actionWithTitle:NSLocalizedStringFromTableInBundle(@"Block Client", @"Localizable",
                                                                                self.bundle, nil)
                                       image:[UIImage systemImageNamed:@"hand.raised.fill"]
                                  identifier:nil
                                     handler:^(__kindof UIAction *_Nonnull action) {
                                         [self disconnectClientWithId:cid block:YES];
                                     }];
                         block.attributes = UIMenuElementAttributesDestructive;

                         return [UIMenu menuWithTitle:@"" children:@[ copyId, copyHost, disconnect, block ]];
                     }];
}

@end
