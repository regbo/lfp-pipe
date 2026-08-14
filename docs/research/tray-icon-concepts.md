# LFP Pipe tray icon concepts

## Second pass

Four additional concepts explore simpler silhouettes and more literal pipe
behavior. All remain transparent, single-color SVGs designed for 16–32 px tray
rendering.

| Option | Concept | Full preview | 16 px | 24 px | 32 px |
| --- | --- | --- | --- | --- | --- |
| C | **Pipe Bridge** — an upright inlet turns through a broad bend into a horizontal outlet; architectural and calm. | <img src="assets/tray-icon-bridge.svg" width="96" height="96" alt="Pipe Bridge icon"> | <img src="assets/tray-icon-bridge.svg" width="16" height="16" alt="Pipe Bridge at 16 pixels"> | <img src="assets/tray-icon-bridge.svg" width="24" height="24" alt="Pipe Bridge at 24 pixels"> | <img src="assets/tray-icon-bridge.svg" width="32" height="32" alt="Pipe Bridge at 32 pixels"> |
| D | **Switchback** — an offset S-route makes the idea of carrying traffic between two endpoints explicit. | <img src="assets/tray-icon-switchback.svg" width="96" height="96" alt="Switchback icon"> | <img src="assets/tray-icon-switchback.svg" width="16" height="16" alt="Switchback at 16 pixels"> | <img src="assets/tray-icon-switchback.svg" width="24" height="24" alt="Switchback at 24 pixels"> | <img src="assets/tray-icon-switchback.svg" width="32" height="32" alt="Switchback at 32 pixels"> |
| E | **Manifold** — a compact four-port junction emphasizes routing and multiple simultaneous connections. | <img src="assets/tray-icon-manifold.svg" width="96" height="96" alt="Manifold icon"> | <img src="assets/tray-icon-manifold.svg" width="16" height="16" alt="Manifold at 16 pixels"> | <img src="assets/tray-icon-manifold.svg" width="24" height="24" alt="Manifold at 24 pixels"> | <img src="assets/tray-icon-manifold.svg" width="32" height="32" alt="Manifold at 32 pixels"> |
| F | **Pipe Loop** — a reduced lowercase `p` built as a continuous return loop, closest to the LFP monogram. | <img src="assets/tray-icon-loop.svg" width="96" height="96" alt="Pipe Loop icon"> | <img src="assets/tray-icon-loop.svg" width="16" height="16" alt="Pipe Loop at 16 pixels"> | <img src="assets/tray-icon-loop.svg" width="24" height="24" alt="Pipe Loop at 24 pixels"> | <img src="assets/tray-icon-loop.svg" width="32" height="32" alt="Pipe Loop at 32 pixels"> |

**Option D, Switchback** is the selected production mark. Its offset route is
recognizable at tray scale and communicates traffic moving between two
endpoints without relying on the LFP letterforms. The Rust tray renderer in
`client/src/desktop.rs` reproduces this source geometry directly.

## First pass

These concepts combine the LFP Connect coral and lowercase monogram language
with a pipe silhouette. Both are transparent, single-color SVGs designed to
remain legible in a 16–32 px system tray.

| Option | Concept | Full preview | 16 px | 24 px | 32 px |
| --- | --- | --- | --- | --- | --- |
| A | **Pipe P** — keeps the recognizable lowercase `p` from the LFP monogram and turns its stem into a pipe with a coupling collar. | <img src="assets/tray-icon-pipe-p.svg" width="96" height="96" alt="Pipe P icon"> | <img src="assets/tray-icon-pipe-p.svg" width="16" height="16" alt="Pipe P at 16 pixels"> | <img src="assets/tray-icon-pipe-p.svg" width="24" height="24" alt="Pipe P at 24 pixels"> | <img src="assets/tray-icon-pipe-p.svg" width="32" height="32" alt="Pipe P at 32 pixels"> |
| B | **Route Elbow** — borrows the tall lowercase `l` posture from the LFP monogram and makes the network route/pipe idea immediate. | <img src="assets/tray-icon-route-elbow.svg" width="96" height="96" alt="Route Elbow icon"> | <img src="assets/tray-icon-route-elbow.svg" width="16" height="16" alt="Route Elbow at 16 pixels"> | <img src="assets/tray-icon-route-elbow.svg" width="24" height="24" alt="Route Elbow at 24 pixels"> | <img src="assets/tray-icon-route-elbow.svg" width="32" height="32" alt="Route Elbow at 32 pixels"> |

## Decision

**Option B, Route Elbow** was the first-pass selection before the Switchback
direction was chosen.

## Rebranding

Each source has one color declaration at the top:

```css
.icon { fill: #ff6f61; }
```

Change that value to create a branded build; no path geometry needs to change.
The current default is LFP Connect coral (`#ff6f61`). The artwork contains no
background or second fixed color, so the same geometry also works for a
platform-provided monochrome template icon.

For the Rust tray renderer, mirror the same separation: keep the selected SVG
path geometry stable and feed the configured brand color into `Paint`.

## Production notes

- Export/rasterize explicitly at 16, 20, 24, and 32 px; do not downscale a
  large PNG at runtime.
- Keep the transparent padding and avoid adding a containing square. Native tray
  surfaces already provide their own visual container.
- Test the chosen mark on Windows light/dark taskbars and as a macOS template
  image before replacing the existing tray monogram.
- These are research concepts, not additions to the managed production brand
  catalog in `controlplane/web/assets`.
