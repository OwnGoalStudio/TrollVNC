#!/bin/bash

set -e

if [ "$THEOS_PACKAGE_SCHEME" = "rootless" ]; then
    /usr/libexec/PlistBuddy -c 'Set :ProgramArguments:0 /var/jb/usr/bin/trollvncserver' "$THEOS_STAGING_DIR/Library/LaunchDaemons/com.82flex.trollvnc.plist"
    /usr/libexec/PlistBuddy -c 'Set :StandardOutPath /var/jb/tmp/trollvnc-stdout.log' "$THEOS_STAGING_DIR/Library/LaunchDaemons/com.82flex.trollvnc.plist"
    /usr/libexec/PlistBuddy -c 'Set :StandardErrorPath /var/jb/tmp/trollvnc-stderr.log' "$THEOS_STAGING_DIR/Library/LaunchDaemons/com.82flex.trollvnc.plist"
fi

if [ -z "$THEBOOTSTRAP" ]; then
    exit 0
fi

# Set version information
GIT_COMMIT_COUNT=$(git rev-list --count HEAD)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $GIT_COMMIT_COUNT" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $PACKAGE_VERSION" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/Info.plist"

# Collect executables
cp -rp "$THEOS_STAGING_DIR/usr/bin/trollvncserver" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/"
cp -rp "$THEOS_STAGING_DIR/usr/bin/trollvncmanager" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/"

# Collect bundle resources
cp -rp "$THEOS_STAGING_DIR/Library/PreferenceBundles/TrollVNCPrefs.bundle" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/"
rm -f "$THEOS_STAGING_DIR/Applications/TrollVNC.app/TrollVNCPrefs.bundle/TrollVNCPrefs"
cp -rp "$THEOS_STAGING_DIR/usr/share/trollvnc/webclients" "$THEOS_STAGING_DIR/Applications/TrollVNC.app/"

# Remove unused files
rm -rf "${THEOS_STAGING_DIR:?}/usr"
rm -rf "${THEOS_STAGING_DIR:?}/Library"

# Pseudo code signing
ldid -Sapp/TrollVNC/TrollVNC/TrollVNC.entitlements "$THEOS_STAGING_DIR/Applications/TrollVNC.app"
