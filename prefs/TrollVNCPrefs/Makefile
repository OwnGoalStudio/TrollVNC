ARCHS := arm64 arm64e
TARGET := iphone:clang:16.5:14.0

INSTALL_TARGET_PROCESSES := Preferences

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME := TrollVNCPrefs

# TrollVNCPrefs_FILES += DpkgVersion.m
# TrollVNCPrefs_FILES += GitHubReleaseUpdater.m
TrollVNCPrefs_FILES += TVNCClientCell.m
TrollVNCPrefs_FILES += TVNCClientListController.m
TrollVNCPrefs_FILES += TVNCListItemsController.m
TrollVNCPrefs_FILES += TVNCRootListController.m
TrollVNCPrefs_FILES += TVNCSliderCell.m
TrollVNCPrefs_FILES += StripedTextTableViewController.m
TrollVNCPrefs_FILES += ZTSelfSignedCertificate.m

TrollVNCPrefs_CFLAGS += -fobjc-arc
TrollVNCPrefs_CFLAGS += -DPACKAGE_VERSION=\"$(PACKAGE_VERSION)\"
TrollVNCPrefs_CFLAGS += -DTHEOS_PACKAGE_SCHEME=\"$(THEOS_PACKAGE_SCHEME)\"

TrollVNCPrefs_FRAMEWORKS += UIKit
TrollVNCPrefs_PRIVATE_FRAMEWORKS += Preferences
TrollVNCPrefs_INSTALL_PATH += /Library/PreferenceBundles

include $(THEOS_MAKE_PATH)/bundle.mk
