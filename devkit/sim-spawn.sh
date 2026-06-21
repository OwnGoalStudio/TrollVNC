#!/bin/bash

cd "$(dirname "$0")"/.. || exit 1

SIMULATOR_IDS=$(xcrun simctl list devices available | grep -E Booted | sed "s/^[ \t]*//" | tr " " "\n")

REAL_SIMULATOR_ID=
for SIMULATOR_ID in $SIMULATOR_IDS; do
    SIMULATOR_ID=${SIMULATOR_ID//[()]/}
    if [[ $SIMULATOR_ID =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]]; then
        REAL_SIMULATOR_ID=$SIMULATOR_ID
        break
    fi
done

if [ -z "$REAL_SIMULATOR_ID" ]; then
    echo "No booted simulator found"
    exit 1
fi

BINARY=".theos/obj/iphone_simulator/debug/trollvncserver"
if [ ! -f "$BINARY" ]; then
    BINARY=".theos/obj/iphone_simulator/trollvncserver"
fi

SANDBOX_PATH=$(xcrun simctl get_app_container "$REAL_SIMULATOR_ID" com.82flex.TrollVNCApp data 2>/dev/null)
if [ -z "$SANDBOX_PATH" ]; then
    echo "Warning: could not resolve app sandbox path; preferences may not load"
fi

STDOUT_LOG="$SANDBOX_PATH/tmp/trollvnc-stdout.log"
STDERR_LOG="$SANDBOX_PATH/tmp/trollvnc-stderr.log"

if [ -n "$SANDBOX_PATH" ]; then
    mkdir -p "$SANDBOX_PATH/tmp"
fi

echo "Logs: $STDOUT_LOG"
echo "      $STDERR_LOG"

SERVER_ARGS=("$@")
if [ "$#" -eq 0 ]; then
    SERVER_ARGS=(-daemon)
fi

SIMCTL_CHILD_TROLLVNC_SANDBOX_PATH="$SANDBOX_PATH" xcrun simctl spawn "$REAL_SIMULATOR_ID" "$BINARY" \
    "${SERVER_ARGS[@]}" \
    > >(tee "$STDOUT_LOG") 2> >(tee "$STDERR_LOG" >&2)
