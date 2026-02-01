#!/usr/bin/env bash
set -euo pipefail

# Generate prefs/TrollVNCPrefs/Resources/Managed.plist from environment variables
# All inputs are provided via environment variables set by the CI workflow.

PLIST="prefs/TrollVNCPrefs/Resources/Managed.plist"
mkdir -p "$(dirname "$PLIST")"

# Header
cat > "$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
EOF

# Helpers
add_bool() { # key, value(true/false)
  local k="$1" v="${2:-}"
  if [[ "$v" == "true" || "$v" == "True" || "$v" == "TRUE" ]]; then
    echo "  <key>$k</key>" >> "$PLIST"
    echo "  <true/>" >> "$PLIST"
  else
    echo "  <key>$k</key>" >> "$PLIST"
    echo "  <false/>" >> "$PLIST"
  fi
}

add_str() { # key, value (non-empty)
  local k="$1" v="${2:-}"
  if [[ -n "$v" ]]; then
    # Basic XML escape for &, <, >
    v="${v//&/&amp;}"; v="${v//</&lt;}"; v="${v//>/&gt;}"
    echo "  <key>$k</key>" >> "$PLIST"
    echo "  <string>$v</string>" >> "$PLIST"
  fi
}

add_int() { # key, value (non-empty)
  local k="$1" v="${2:-}"
  if [[ -n "$v" ]]; then
    echo "  <key>$k</key>" >> "$PLIST"
    echo "  <integer>$v</integer>" >> "$PLIST"
  fi
}

add_real() { # key, value (non-empty)
  local k="$1" v="${2:-}"
  if [[ -n "$v" ]]; then
    echo "  <key>$k</key>" >> "$PLIST"
    echo "  <real>$v</real>" >> "$PLIST"
  fi
}

# Booleans (always add)
add_bool Enabled               "${TVNC_ENABLED:-}"
add_bool ClipboardEnabled      "${TVNC_CLIPBOARD_ENABLED:-}"
add_bool ViewOnly              "${TVNC_VIEW_ONLY:-}"
add_bool SingleNotifEnabled    "${TVNC_SINGLE_NOTIF_ENABLED:-}"
add_bool ClientNotifsEnabled   "${TVNC_CLIENT_NOTIFS_ENABLED:-}"
add_bool OrientationSync       "${TVNC_ORIENTATION_SYNC:-}"
add_bool OrientationPadFix     "${TVNC_ORIENTATION_PAD_FIX:-}"
add_bool NaturalScroll         "${TVNC_NATURAL_SCROLL:-}"
add_bool AutoAssistEnabled     "${TVNC_AUTO_ASSIST_ENABLED:-}"
add_bool ServerCursor          "${TVNC_SERVER_CURSOR:-}"
add_bool AsyncSwap             "${TVNC_ASYNC_SWAP:-}"
add_bool BonjourEnabled        "${TVNC_BONJOUR_ENABLED:-}"
add_bool KeyLogging            "${TVNC_KEY_LOGGING:-}"

# Strings (optional)
add_str DesktopName            "${TVNC_DESKTOP_NAME:-}"
add_str FrameRateSpec          "${TVNC_FRAME_RATE_SPEC:-}"
add_str WheelTuning            "${TVNC_WHEEL_TUNING:-}"
add_str HttpDir                "${TVNC_HTTP_DIR:-}"
add_str SslCertFile            "${TVNC_SSL_CERT_FILE:-}"
add_str SslKeyFile             "${TVNC_SSL_KEY_FILE:-}"
# Reverse
add_str ReverseMode            "${TVNC_REVERSE_MODE:-}"
add_str ReverseSocket          "${TVNC_REVERSE_SOCKET:-}"
# Auth passwords
add_str FullPassword           "${TVNC_FULL_PASSWORD:-}"
add_str ViewOnlyPassword       "${TVNC_VIEWONLY_PASSWORD:-}"
# Modifier map
add_str ModifierMap            "${TVNC_MODIFIER_MAP:-}"

# Integers (optional)
add_int Port                           "${TVNC_PORT:-}"
add_int MaxInflight                    "${TVNC_MAX_INFLIGHT:-}"
add_int TileSize                       "${TVNC_TILE_SIZE:-}"
add_int FullscreenThresholdPercent     "${TVNC_FULLSCREEN_THRESHOLD_PERCENT:-}"
add_int MaxRects                       "${TVNC_MAX_RECTS:-}"
add_int HttpPort                       "${TVNC_HTTP_PORT:-}"
add_int ReverseRepeaterID              "${TVNC_REVERSE_REPEATER_ID:-}"

# Reals (optional)
add_real KeepAliveSec         "${TVNC_KEEPALIVE_SEC:-}"
add_real Scale                "${TVNC_SCALE:-}"
add_real DeferWindowSec       "${TVNC_DEFER_WINDOW_SEC:-}"
add_real WheelStepPx          "${TVNC_WHEEL_STEP_PX:-}"

# Footer
cat >> "$PLIST" <<'EOF'
</dict>
</plist>
EOF

# Ensure valid XML
plutil -convert xml1 "$PLIST"

echo "Managed configuration generated at $PLIST"
