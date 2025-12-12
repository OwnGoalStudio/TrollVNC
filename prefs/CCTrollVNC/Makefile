ARCHS := arm64 arm64e
TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES := SpringBoard

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME := CCTrollVNC

CCTrollVNC_BUNDLE_EXTENSION += bundle

CCTrollVNC_FILES += CCTrollVNC.mm
CCTrollVNC_CFLAGS += -fobjc-arc
CCTrollVNC_FRAMEWORKS += UIKit
CCTrollVNC_PRIVATE_FRAMEWORKS += ControlCenterUIKit
CCTrollVNC_INSTALL_PATH += /Library/ControlCenter/Bundles

include $(THEOS_MAKE_PATH)/bundle.mk
