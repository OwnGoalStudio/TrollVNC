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

#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>

#import "BulletinManager.h"
#import "Logging.h"

#define BANNER_CATEGORY "com.82flex.trollvnc.notification-category.standard"

@interface UNUserNotificationCenter (Private)
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
@end

@implementation BulletinManager {
    NSString *mSectionIdentifier;
    UNUserNotificationCenter *mNotificationCenter;
    NSString *mSingleNotificationIdentifier;
}

+ (instancetype)sharedManager {
    static BulletinManager *sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedManager = [[BulletinManager alloc] init];
    });
    return sharedManager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
#ifdef THEBOOTSTRAP
        mSectionIdentifier = @"com.82flex.TrollVNCApp";
#else
        mSectionIdentifier = @"com.apple.Preferences";
#endif

        mNotificationCenter = [[UNUserNotificationCenter alloc] initWithBundleIdentifier:mSectionIdentifier];

        UNNotificationCategory *showTitleCategory = [UNNotificationCategory categoryWithIdentifier:@BANNER_CATEGORY
                                                                                           actions:@[]
                                                                                 intentIdentifiers:@[]
                                                                                           options:kNilOptions];

        [mNotificationCenter setNotificationCategories:[NSSet setWithObjects:showTitleCategory, nil]];

        mSingleNotificationIdentifier = nil;
    }
    return self;
}

- (void)updateSingleBannerWithContent:(NSString *)messageContent
                           badgeCount:(NSInteger)badgeCount
                             userInfo:(NSDictionary *)userInfo {

    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];

    content.title = @"TrollVNC";
    content.body = messageContent;
    content.categoryIdentifier = @BANNER_CATEGORY;
    content.threadIdentifier = mSectionIdentifier;
    content.userInfo = userInfo;

#ifdef THEBOOTSTRAP
    content.badge = @(badgeCount);
#endif

    if (@available(iOS 15.0, *)) {
        if ([content respondsToSelector:@selector(setInterruptionLevel:)])
            content.interruptionLevel = UNNotificationInterruptionLevelPassive;
    }

    if (mSingleNotificationIdentifier) {
        [mNotificationCenter removePendingNotificationRequestsWithIdentifiers:@[ mSingleNotificationIdentifier ]];
        [mNotificationCenter removeDeliveredNotificationsWithIdentifiers:@[ mSingleNotificationIdentifier ]];
    }

    UNNotificationTrigger *trigger = [UNTimeIntervalNotificationTrigger triggerWithTimeInterval:0.33 repeats:NO];

    mSingleNotificationIdentifier = [[NSUUID UUID] UUIDString];
    UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:mSingleNotificationIdentifier
                                                                          content:content
                                                                          trigger:trigger];

    [mNotificationCenter addNotificationRequest:request withCompletionHandler:nil];
}

- (void)popBannerWithContent:(NSString *)messageContent userInfo:(NSDictionary *)userInfo {

    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];

    content.title = @"TrollVNC";
    content.body = messageContent;
    content.categoryIdentifier = @BANNER_CATEGORY;
    content.threadIdentifier = mSectionIdentifier;
    content.userInfo = userInfo;
    content.sound = [UNNotificationSound defaultSound];

    if (@available(iOS 15.0, *)) {
        if ([content respondsToSelector:@selector(setInterruptionLevel:)])
            content.interruptionLevel = UNNotificationInterruptionLevelActive;
    }

    NSString *uuidString = [[NSUUID UUID] UUIDString];
    UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:uuidString
                                                                          content:content
                                                                          trigger:nil];

    [mNotificationCenter addNotificationRequest:request withCompletionHandler:nil];
}

- (void)revokeSingleNotification {
    [self resetBadgeCount];
    if (mSingleNotificationIdentifier) {
        [mNotificationCenter removePendingNotificationRequestsWithIdentifiers:@[ mSingleNotificationIdentifier ]];
        [mNotificationCenter removeDeliveredNotificationsWithIdentifiers:@[ mSingleNotificationIdentifier ]];
        mSingleNotificationIdentifier = nil;
    }
}

- (void)revokeAllNotifications {
    mSingleNotificationIdentifier = nil;
    [mNotificationCenter removeAllPendingNotificationRequests];
    [mNotificationCenter removeAllDeliveredNotifications];
}

#pragma mark - Private Methods

- (void)resetBadgeCount {
#ifdef THEBOOTSTRAP
    if (@available(iOS 16, *)) {
        [mNotificationCenter setBadgeCount:0
                     withCompletionHandler:^(NSError *_Nullable error) {
                         if (error) {
                             TVLog(@"Error setting badge count: %@", error);
                         }
                     }];
    } else {
        [self updateSingleBannerWithContent:@"" badgeCount:0 userInfo:nil];
    }
#endif
}

@end