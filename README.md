# TrollVNC

[now-on-havoc]: https://havoc.app/search/TrollVNC

[<img width="150" src="https://docs.havoc.app/img/badges/get_square.svg" />][now-on-havoc]

TrollVNC is a VNC server for iOS devices, allowing remote access and control of the device’s screen.

<img width="763" alt="screenshot tiny" src="https://github.com/user-attachments/assets/2d2cd457-a3d2-475a-b391-e3232d747f48" />

## Features

- Low-latency capture with scaling, frame rate control, and back-pressure.
- Optional dirty-region updates for bandwidth savings.
- Tunable scroll wheel gestures and natural direction toggle.
- UTF‑8 Clipboard sync (UltraVNC).
- Orientation sync and rotation-aware input mapping.
- Optional server-side cursor overlay.
- Classic VNC authentication with full-access and view-only passwords.
- Built-in HTTP/WebSockets for browser access (HTTPS/WSS supported).
- Enable secure WebSocket connections without pain.
- Bonjour/mDNS auto-discovery on the local network.
- [Reverse VNC](#reverse-vnc-reverse-connection)
- [Pre-seeded configuration](#managed-configuration-preconfigured-deployment)

## Usage

1. Fork this repo and run GitHub workflow “Build TrollVNC”.
2. Download “TrollVNC” from Releases and install it on your iOS device.
3. Configure the VNC server settings from “Settings” → “TrollVNC” or the standalone “TrollVNC” app as needed.
4. Or, run the following command on iOS device or simulator:

```sh
trollvncserver -p 5901 -n "My iPhone" [options]
```

### Options

**Basic**:

- `-p port`   TCP port for VNC (default: `5901`)
- `-c port`   TCP port for client management (listening on localhost only; `0` disables, default: `0`)
- `-n name`   Desktop name shown to clients (default: `TrollVNC`)
- `-v`        View-only (ignore input)
- `-A sec`    Keep-alive interval to prevent device sleep by sending harmless dummy key events; only active while at least one client is connected (`15..86400`, `0` disables, default: `0`)

**Display/Performance**:

- `-s scale`  Output scale factor (`0 < s <= 1`, default: `1.0`; `1` means no scaling)
- `-F spec`   Frame rate: single `fps`, range `min-max`, or full `min:pref:max`; on iOS 15+ a range is applied, on iOS 14 the max (or preferred) is used
- `-d sec`    Defer update window in seconds to coalesce changes (`0..0.5`, default: `0.015`)
- `-Q n`      Max in-flight updates before dropping new frames (`0..8`, default: `2`; `0` disables dropping)

**Dirty detection**:

- `-t size`   Tile size for dirty-detection in pixels (`8..128`, default: `32`)
- `-P pct`    Fullscreen fallback threshold percent (`0..100`, default: `0`; `0` disables dirty detection entirely)
- `-R max`    Max dirty rects before collapsing to a bounding box (default: `256`)
- `-a`        Enable non-blocking swap (may cause tearing).

**Scroll/Input**:

- `-W px`     Wheel step in pixels per tick (`0` disables, default: `48`)
- `-w k=v,..` Wheel tuning keys: `step,coalesce,max,clamp,amp,cap,minratio,durbase,durk,durmin,durmax`
- `-N`        Natural scroll direction (invert wheel delta)
- `-M scheme` Modifier mapping: `std|altcmd` (default: `std`)
- `-K`        Log keyboard events (keysym -> mapping) to stderr

**HTTP/WebSockets**:

- `-H port`   Enable built-in HTTP server on port (`0` disables; default `0`)
- `-D path`   Absolute path for HTTP document root
- `-e file`   Path to SSL certificate file
- `-k file`   Path to SSL private key file

**Discovery**:

- `-B on|off` Enable Bonjour/mDNS advertisement for auto-discovery by viewers on the local network (default: `on`)

**Accessibility**:

- `-O on|off` Sync UI orientation and rotate output (default: `on`)
- `-E on|off` Enable AssistiveTouch auto-activation (default: `off`)
- `-U on|off` Enable server-side cursor overlay (default: `off`)

**Notifications**:

- `-i on|off` Enable a single user notification when the first client connects (default: `on`)
- `-I on|off` Enable user notifications for client connect/disconnect (default: `on`)

**Extensions**:

- `-C on|off` Enable UltraVNC UTF-8 clipboard extension (default: `on`)
- `-T on|off` Enable TightVNC 1.x file transfer extension (default: `off`)

**Logging**:

- `-V`        Enable verbose logging (debug only)

**Help**:

- `-h`        Show built-in help message

**Reverse Connection**:

- `-reverse host:port`  Connect out to a listening VNC viewer (TightVNC/UltraVNC). IPv6 as `[addr]:port`.
- `-repeater id host:port`  Connect out to an UltraVNC Repeater (Mode II) with numeric `id`; `host:port` is the repeater’s server (invers) port (often `5500`).

> When reverse is enabled, TrollVNC disables the local VNC port (`-p`), HTTP/WebSockets (`-H`), and Bonjour (`-B`). See “Reverse VNC” below for full setup with examples.

### Key Input Mapping

**Mouse**:

- **Left button**: single-finger touch. Hold to drag; move updates while held.
- **Right button**: Home/Menu button. Press = short press; hold ≈ long press. Release ends the press.
- **Middle button**: Power button. Press = short press; hold ≈ long press. Release ends the press.
- **Wheel**: translated into short drags with coalescing/velocity; see “Wheel/Scroll Tuning”.

**Keyboard**:

- Standard ASCII keys, Return/Tab/Backspace/Delete, arrows, Home/End/PageUp/PageDown, and function keys F1..F24 are
  sent as HID keyboard usages.
- Modifier mapping (`-M`):
  - `std` (default): Alt -> Option; Meta/Super -> Command.
  - `altcmd` (macOS): Alt -> Command; Meta -> Option; Super -> Command.
- Media/consumer keys (when the client sends XF86 keysyms):
  - Brightness Up/Down -> display brightness increment/decrement
  - Volume Up/Down/Mute -> volume increment/decrement/mute
  - Previous / Play-Pause / Next -> previous track / toggle play-pause / next track

> Touch, scroll, and button mappings respect the current rotation when `-O on` is used.

**AssistiveTouch Auto-Activation (`-E on`)**:

- When the first client connects, TrollVNC enables AssistiveTouch if it’s currently off; when the last client disconnects,
  it restores the previous state (disables it only if TrollVNC enabled it).
- Applies on device builds; no-op on the simulator.

## Performance Tips

Quick guidance on key trade-offs (latency vs. bandwidth vs. CPU/battery):

- `-s scale`: Biggest lever for bandwidth and encoder CPU. Start at `0.66–0.75` for text-heavy UIs; use `0.5` for tight links or slow networks; `1.0` for pixel-perfect.
- `-F spec`: Cap preferred frame rate to balance smoothness and battery. `30–60` is a sensible range; on 120 Hz devices, `60` often suffices. On iOS 14 the max (or preferred if provided) value is used.
- `-d sec`: Coalesce updates. Larger values lower CPU/bitrate but add latency. Typical range `0.005–0.030`; interactive UIs prefer `≤ 0.015`.
- `-Q n`: Throughput vs. latency backpressure. `1–2` recommended. `0` disables dropping and can grow latency when encoders are slow.
- `-t size`: Dirty-detection tile size. `32` default; `64` cuts hashing/rect overhead on slower devices; `16` (or `8`) captures finer UI details at higher CPU cost.
- `-P pct`: Fullscreen fallback threshold. Practical `25–40`; higher values stick to rect updates longer. `0` disables dirty detection (always fullscreen).
- `-R max`: Rect cap before collapsing to a bounding box. `128–512` common; too high increases RFB overhead.
- `-a`: Non-blocking swap. Can reduce stalls/contension; may introduce tearing. Try if you see occasional stalls; leave off for maximal visual stability. If a non-blocking swap cannot lock clients, TrollVNC falls back to copying only dirty rectangles to the front buffer to minimize tearing and bandwidth.

**Notes:**

- Scaling happens before dirty detection; tile size applies to the scaled frame. Effective tile size in source pixels ≈ t / scale.
- With `-Q 0`, frames are never dropped. If the client or network is slow, input-to-display latency can grow.
- On older devices, prefer lowering `-s` and increasing `-t` to reduce CPU and memory bandwidth.

### Preset Examples

By default, dirty detection is **disabled** because it usually has a high CPU cost. You can enable it with `-P` to set a fullscreen fallback threshold.

Low-latency interactive (LAN):

```sh
trollvncserver -p 5901 -n "My iPhone" -s 0.75 -d 0.008 -Q 1 -t 32 -P 35 -R 512
```

Battery/bandwidth saver (cellular/WAN):

```sh
trollvncserver -p 5901 -n "My iPhone" -s 0.5 -d 0.025 -Q 2 -t 64 -P 50 -R 128
```

High quality on fast LAN:

```sh
trollvncserver -p 5901 -n "My iPhone" -s 1.0 -d 0.012 -Q 2 -t 32 -P 30 -R 512
```

Choppy network (high RTT/loss):

```sh
trollvncserver -p 5901 -n "My iPhone" -s 0.66 -d 0.035 -Q 1 -t 64 -P 60 -R 128
```

Older devices (CPU-limited):

```sh
trollvncserver -p 5901 -n "My iPhone" -s 0.5 -d 0.02 -Q 1 -t 64 -P 40 -R 256
```

Optional: add `-a` to any profile if you observe occasional stalls due to encoder contention; remove it if tearing is noticeable:

```sh
trollvncserver ... -a
```

### Frame Rate Control

Use `-F` to set the `CADisplayLink` frame rate:

- Single value: `-F 60`
- Range: `-F 30-60`
- Full range with preferred: `-F 30:60:120`

**Notes:**

- On iOS 15+, the full range is applied via `preferredFrameRateRange`.
- On iOS 14, only `preferredFramesPerSecond` is available, so the max (or preferred if provided) is used.

### Keep-Alive (Prevent Sleep)

Use `-A` to periodically send a harmless dummy key event to keep the device awake while clients are connected.

## Wheel/Scroll Tuning

The scroll wheel is emulated with short drags. Fast wheel motion becomes one longer flick; slow motion becomes short drags. You can tune its feel at runtime:

- `-W px`: Base pixels per wheel tick (`0` disables, default `48`). Larger = faster scrolls.
- `-w k=v,...` keys:
  - `step`: same as `-W` (pixels)
  - `coalesce`: coalescing window in seconds (default `0.03`, `0..0.5`)
  - `max`: base max distance per gesture before clamp (default `192`)
  - `clamp`: absolute clamp factor, final max distance = clamp × max (default `2.5`)
  - `amp`: velocity amplification coefficient for fast scrolls (default `0.18`)
  - `cap`: max extra amplification (default `0.75`)
  - `minratio`: minimum effective distance vs step for tiny scrolls (default `0.35`)
  - `durbase`: gesture duration base in seconds (default `0.05`)
  - `durk`: gesture duration factor applied to sqrt(distance) (default `0.00016`)
  - `durmin`: min gesture duration (default `0.05`)
  - `durmax`: max gesture duration (default `0.14`)
  - `natural`: `1` to enable natural direction, `0` to disable

**Examples**:

Smooth and slow:

```sh
trollvncserver ... -W 32 -w minratio=0.3,durbase=0.06,durmax=0.16
```

Fast long scrolls:

```sh
trollvncserver ... -W 64 -w amp=0.25,cap=1.0,max=256,clamp=3.0
```

More sensitive small scrolls:

```sh
trollvncserver ... -w minratio=0.5,durbase=0.055
```

Disable wheel entirely:

```sh
trollvncserver ... -W 0
```

## Clipboard Sync

_Many VNC clients support clipboard sync, but behavior may vary. This feature is primarily supported by UltraVNC._

- UTF-8 clipboard sync is enabled by default; fallbacks to Latin-1 for legacy clients where needed.
- Starts when the first client connects and stops when the last disconnects.
- Disable it with `-C off` if not desired.

## Rotate / Orientation

When `-O on` is set, TrollVNC tracks iOS interface orientation and rotates the outgoing framebuffer to match (0°, 90°, 180°, 270°). Touch and scroll input are mapped into the device coordinate space with the correct axis and direction in all orientations.

## Server-Side Cursor

TrollVNC does not draw a cursor by default; most VNC viewers render their own pointer. If your viewer expects the server to render a cursor, enable it with `-U on`.

## Authentication

Classic VNC authentication can be enabled via environment variables:

- `TROLLVNC_PASSWORD`: full-access password. Enables VNC auth when set.
- `TROLLVNC_VIEWONLY_PASSWORD`: optional view-only password. When present, clients authenticating with this password can view but cannot send input.

**Examples**:

```sh
export TROLLVNC_PASSWORD=editpass
export TROLLVNC_VIEWONLY_PASSWORD=viewpass   # optional
trollvncserver -p 5901 -n "My iPhone"
```

**Notes**:

- Classic VNC only uses the first 8 characters of each password.
- You must set a password if you’re using the built-in VNC client of macOS.
- `-v` forces global view-only regardless of password. View-only password applies per client.

## HTTP / WebSockets

TrollVNC can start LibVNCServer’s built-in HTTP server to serve a browser-based VNC client, [noVNC](https://github.com/novnc/noVNC).

- When `-H` is non-zero, the HTTP server listens on that port.
- If `-D` is provided, its absolute path is used as `httpDir`. If omitted, TrollVNC derives a default `httpDir` relative to the executable `../share/trollvnc/webclients`.
- HTTP proxy CONNECT is enabled to support certain viewer flows.

**Examples**:

```sh
# Enable web client on port 5801 using the default web root
trollvncserver -p 5901 -H 5801

# Enable web client on port 8081 with a custom web root
trollvncserver -p 5901 -H 8081 -D /var/www/trollvnc/webclients
```

### Using Secure WebSockets

WSS encrypts the WebSocket transport (TLS for ws).

**Prerequisites**:

- A certificate (`cert.pem`) and private key (`key.pem`) accepted by your browser.
- The built‑in HTTP server enabled on some port with `-H` (it also exposes the WebSocket endpoint).

**Steps**:

Generate or obtain a cert/key (example using a local CA on macOS).

  ```sh
  brew install minica
  minica -ip-addresses "192.168.2.100"
  ```

Trust the CA: import `minica.pem` into your OS/browser trust store (otherwise the browser will warn).

Copy the host cert and key to the device (choose any readable path).

  ```sh
  scp -r 192.168.2.100 root@192.168.2.100:/usr/share/trollvnc/ssl/
  ```

Start TrollVNC with WSS enabled.

  ```sh
  trollvncserver -p 5901 -H 5801 \
    -e /usr/share/trollvnc/ssl/192.168.2.100/cert.pem \
    -k /usr/share/trollvnc/ssl/192.168.2.100/key.pem
  ```

Connect from your browser. Open the bundled web page at `http://<host>:5801/`. The secure endpoint will be available when `-e`/`-k` are provided.

**Notes**:

- The certificate must match what the browser connects to (IP or hostname/SAN).
- Self‑signed setups require trusting the CA or the specific certificate.

## Auto-Discovery (Bonjour/mDNS)

- Publishes a VNC service on the local network via Bonjour/mDNS (type `_rfb._tcp`), using the name from `-n` and the port from `-p`.
- Enabled by default. Toggle with `-B on|off` or in Settings → TrollVNC → “Enable Auto-Discovery”.
- Viewers on the same LAN that support Bonjour can find it automatically; otherwise connect by `ip:port` shown in the app/logs.

## Reverse VNC (Reverse Connection)

TrollVNC can initiate an outbound connection to a listening VNC viewer or an UltraVNC repeater. This avoids opening inbound ports on the device and is helpful behind NAT/firewalls.

When reverse connection is enabled:

- The normal server listening port is disabled (equivalent to not using `-p`).
- The built-in HTTP server is disabled (any `-H` is ignored).
- Bonjour/mDNS advertisement is disabled.
- Classic VNC authentication via environment variables still applies if set (see “Authentication”).

### 1) Viewer mode (Listening Viewer: TightVNC/UltraVNC)

TrollVNC can connect to a viewer running in Listening mode. The viewer listens for inbound reverse connections; TrollVNC dials out.

**Roles and steps**:

#### A) Viewer (Listening)

- Start TightVNC or UltraVNC Viewer in “Listen” mode (UltraVNC: Connections → Listen mode, or Toolbar → Listen).
- Default listening port is `5500`; you can change it in the viewer options.
- Ensure your desktop firewall allows inbound on the chosen listening port.

#### B) Server (TrollVNC, Viewer mode)

- CLI examples (use your viewer’s listening `host:port`):

  ```sh
  # IPv4
  trollvncserver -reverse 203.0.113.10:5500 -n "My iPhone"

  # IPv6
  trollvncserver -reverse [2001:db8::1]:5500 -n "My iPhone"
  ```

- Preferences (Settings → TrollVNC):
  - Reverse Connection → Mode: Viewer
  - Server: `host:port` (e.g., `viewer.example.com:5500` or `[2001:db8::1]:5500`)

**Notes**:

- Only an outbound TCP connection from the device to the viewer is required.
- If your viewer uses a custom port, specify that port in `-reverse host:port` and in the Server field.
- The desktop viewer shows the incoming reverse connection with the name from `-n`.

### 2) Repeater mode (UltraVNC Repeater, Mode II)

TrollVNC can connect to an UltraVNC Repeater in Mode II. Both the Server (TrollVNC) and the Viewer make outbound connections to the Repeater and pair via a numeric ID.

**Roles and steps**:

#### A) Repeater

- Deploy or start an UltraVNC Repeater that both device and viewer can reach (public, DMZ, or with NAT port forwards).
- Common defaults (may vary by setup):
  - Server (invers) port: `5500`
  - Viewer port: `5901` (sometimes `5900`)
- Make a note of the repeater’s `host:port` for the Server side (often `host:5500`) and for the Viewer side (often `host:5901`).

#### B) Server (TrollVNC on iOS)

- Choose a numeric Repeater ID (commonly up to 9 digits). Do not include `ID:` — enter only the number.
- CLI example (use the repeater’s server port):

  ```sh
  trollvncserver -repeater 12345679 repeater.example.com:5500 -n "My iPhone"
  ```

  - `12345679` is the numeric Repeater ID.
  - `repeater.example.com:5500` should point to the repeater’s server (invers) port. IPv6 example: `-repeater 12345679 [2001:db8::1]:5500`

- Preferences (Settings → TrollVNC):
  - Reverse Connection → Mode: UltraVNC Repeater
  - Server: `host:server_port` (e.g., `repeater.example.com:5500` or `[2001:db8::1]:5500`)
  - Repeater ID: numeric (e.g., `12345679`)

Behavior when reverse is enabled: local VNC port is disabled, HTTP/WebSockets are disabled, and Bonjour/mDNS is disabled.

**Optional**: set `TROLLVNC_REPEATER_RETRY_INTERVAL` (seconds) to wait before exit if the connection fails (useful when a supervisor always restarts the process).

#### C) Viewer (Client)

<img width="383" height="198" alt="uvnc_repeater" src="https://github.com/user-attachments/assets/5f5e86a1-605a-4624-8b8e-27ebe89ce4e3" />

- UltraVNC Viewer is recommended for Mode II:
  - Select “Repeater”; in “ID:12345679”, enter `ID:<your_id>` (e.g., `ID:12345679`).
  - Enter the repeater’s viewer address, e.g., `repeater.example.com:5901`.
  - Connect; the repeater pairs the viewer with the server using the matching ID.

**Notes**:

- Connections are outbound from both sides; no inbound port on the iOS device is needed.
- Use the repeater’s server port for TrollVNC (`-repeater <id> host:server_port`) and the viewer port for UltraVNC Viewer.
- UltraVNC “Mode SSL” repeaters require special viewer/server builds; TrollVNC connects to standard (non-SSL) Mode II repeaters.

## Managed Configuration (Preconfigured Deployment)

TrollVNC can be preconfigured via a bundled `Managed.plist` for supervised or fleet deployments where end users shouldn’t change settings.

### How To Use

1. Create `prefs/TrollVNCPrefs/Resources/Managed.plist` in the repo.
2. Populate it with the keys you need (see “Supported keys” below).
3. Build/package the project as usual; the file is embedded into `TrollVNCPrefs.bundle` automatically.
4. Install the build on device. TrollVNC detects `Managed.plist` at startup and applies the configured values.
5. Verify & expected behavior:
   - “Settings” → “TrollVNC” shows a banner: “This TrollVNC instance is managed by your organization”.
   - The preferences UI is effectively locked down.
   - In‑app update prompts are suppressed while managed.
   - Configured values take effect at startup; you don’t need equivalent CLI flags for these options.

### Supported Keys

- Strings:
  - `DesktopName`: Desktop name shown to clients
  - `ModifierMap`: `std` | `altcmd`
  - `FrameRateSpec`: e.g., `"60"`, `"30-60"`, or `"30:60:120"`
  - `WheelTuning`: advanced wheel tuning string, e.g., `"amp=0.25,cap=1.0,max=256,clamp=3.0"`
  - `HttpDir`: absolute path to HTTP doc root
  - `SslCertFile`: absolute path to TLS cert (PEM)
  - `SslKeyFile`: absolute path to TLS key (PEM)
  - Reverse connection:
    - `ReverseMode`: `viewer` | `repeater`
    - `ReverseSocket`: `host:port` or `[ipv6]:port` (preferred)
    - Backward-compat: `ReverseHost` + `ReversePort`
  - Authentication:
    - `FullPassword`: full-access password (first 8 chars used)
    - `ViewOnlyPassword`: view-only password (first 8 chars used)

- Numbers:
  - `Port` (1024..65535; `0`/<1024 is treated as invalid and falls back to 5901)
  - `KeepAliveSec` (0 or 15..300; values 0..15 are treated as 0)
  - `Scale` (0.1..1.0)
  - `DeferWindowSec` (0..0.5)
  - `MaxInflight` (0..8)
  - `TileSize` (8..128)
  - `FullscreenThresholdPercent` (0..100)
  - `MaxRects` (1..4096)
  - `WheelStepPx` (0 disables wheel; else 5..1000)
  - `HttpPort` (0 disables; else 1024..65535)
  - `ReverseRepeaterID` (numeric ID for UltraVNC Repeater Mode II)

- Booleans:
  - `Enabled`, `ClipboardEnabled`, `ViewOnly`, `OrientationSync`, `NaturalScroll`, `ServerCursor`, `AsyncSwap`, `KeyLogging`, `AutoAssistEnabled`, `BonjourEnabled`, `FileTransferEnabled`, `SingleNotifEnabled`, `ClientNotifsEnabled`

**Notes**:

- When reverse connection is enabled via Managed.plist, behavior matches CLI reverse: local VNC port disabled, HTTP/WebSockets disabled, Bonjour disabled.
- `HttpDir`, `SslCertFile`, and `SslKeyFile` must be absolute paths.

### Example Configurations

**Minimal preset**: reverse to a listening viewer with a custom desktop name:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Enabled</key>
  <true/>
  <key>DesktopName</key>
  <string>My iPhone</string>
  <key>ReverseMode</key>
  <string>viewer</string>
  <key>ReverseSocket</key>
  <string>203.0.113.10:5500</string>
  <key>ClipboardEnabled</key>
  <true/>
  <key>KeepAliveSec</key>
  <integer>60</integer>
</dict>
</plist>
```

**LAN example**: enable built‑in HTTP client and TLS:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Enabled</key>
  <true/>
  <key>DesktopName</key>
  <string>TrollVNC</string>
  <key>Port</key>
  <integer>5901</integer>
  <key>Scale</key>
  <real>0.75</real>
  <key>FrameRateSpec</key>
  <string>30:60:120</string>
  <key>DeferWindowSec</key>
  <real>0.012</real>
  <key>MaxInflight</key>
  <integer>2</integer>
  <key>TileSize</key>
  <integer>32</integer>
  <key>FullscreenThresholdPercent</key>
  <integer>35</integer>
  <key>MaxRects</key>
  <integer>512</integer>
  <key>HttpPort</key>
  <integer>5801</integer>
  <key>HttpDir</key>
  <string>/usr/share/trollvnc/webclients</string>
  <key>SslCertFile</key>
  <string>/usr/share/trollvnc/ssl/host/cert.pem</string>
  <key>SslKeyFile</key>
  <string>/usr/share/trollvnc/ssl/host/key.pem</string>
  <key>ClipboardEnabled</key>
  <true/>
  <key>ViewOnly</key>
  <false/>
  <key>FullPassword</key>
  <string>editpass</string>
  <key>ViewOnlyPassword</key>
  <string>viewpass</string>
</dict>
</plist>
```

## Build with GitHub Actions

You can build TrollVNC entirely in GitHub Actions using the built-in workflow.

- Fork this repository (or enable “Actions” in your own clone).
- Go to the “Actions” tab → “Build TrollVNC” → “Run workflow”.
- Choose the branch to run on (usually main) and fill the form inputs below.

### Inputs

Due to a GitHub limit, the manual form exposes 10 commonly used options:

- `is_managed`: whether to bundle a `Managed.plist` (managed deployment)
- `desktop_name`: display name shown to VNC clients
- `port`: VNC TCP port (default `5901`)
- `view_only`: force view-only (ignore input)
- `scale`: output scale (`0.1–1.0`)
- `frame_rate_spec`: frame rate, e.g. `60` | `30-60` | `30:60:120`
- `modifier_map`: std | altcmd
- `reverse_mode`: none | viewer | repeater
- `reverse_socket`: `host:port` or `[ipv6]:port` (for viewer or repeater server port)
- `reverse_repeater_id`: numeric ID (UltraVNC Repeater Mode II)

When `is_managed` is true, the workflow generates a `Managed.plist` from these inputs and bundles it.

### Optional Passwords (Secrets)

You may set these repository secrets so the managed build embeds VNC passwords. If you don’t set them, the keys are omitted.

- `TVNC_FULL_PASSWORD`
- `TVNC_VIEWONLY_PASSWORD`

Add them under: “Settings” → “Secrets and variables” → “Actions” → “New repository secret”.

### Fixed Defaults in CI (Managed Builds)

In the workflow-managed build, the following keys are fixed to safe defaults:

- `Enabled=true`
- `ClipboardEnabled=true`
- `SingleNotifEnabled=true`
- `ClientNotifsEnabled=true`
- `KeepAliveSec=15`
- `OrientationSync=true`
- `NaturalScroll=false`
- `AutoAssistEnabled=false`
- `ServerCursor=false`
- `BonjourEnabled=false`
- `KeyLogging=false`

For advanced tuning (HTTP/TLS, wheel tuning, dirty detection, etc.), commit your own `prefs/TrollVNCPrefs/Resources/Managed.plist` to the repo and leave `is_managed` unchecked, or extend the workflow locally.

### Artifacts and Releases

- Each run uploads artifacts per scheme:
  - `packages-default`, `packages-rootless`, `packages-roothide`, `packages-bootstrap`
  - `dsym-default`, `dsym-rootless`, `dsym-roothide`, `dsym-bootstrap`
- Download them from the run page → `Artifacts`.
- If you push to the `release` branch (and the workflow runs there), a GitHub Release is created automatically with packaged files attached.

## Build Dependencies

See: <https://github.com/Lessica/BuildVNCServer>

## Acknowledgements

- [libvncserver](https://github.com/LibVNC/libvncserver)
- [libjpeg-turbo](https://github.com/libjpeg-turbo/libjpeg-turbo)
- [libpng](https://github.com/pnggroup/libpng)
- [OpenSSL](https://github.com/openssl/openssl)
- [Cyrus SASL](https://github.com/cyrusimap/cyrus-sasl)
- The majority of the main program `src/trollvncserver.mm` was written/generated by GitHub Copilot (GPT-5).

## License

TrollVNC is an open-source VNC solution, licensed under GPLv2. You are free to access, use, and modify the source code. See the [COPYING](COPYING) file for more information.

### Why pay for TrollVNC?

- Ready-to-use, pre-compiled builds
- Automatic updates and continuous improvements
- Priority support and troubleshooting assistance
- Sustainable development through your contribution

If you prefer, you can always build TrollVNC yourself directly from the source.

### Your choice

- Compile for free.
- Pay for convenience, updates, and support.

Support TrollVNC and help us keep remote access fast, secure, and evolving.
