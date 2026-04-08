# UI Demo

This directory contains a standalone dashboard demo based on the provided `daed` screenshot and wired to the repository's existing control API.

## Files

- `index.html`: page structure
- `styles.css`: layout and visual style
- `script.js`: control API client, proxy interactions, and traffic chart rendering

## API Integration

The demo connects to dae's Clash-style external controller in `controlapi/`.

- HTTP endpoints used:
  - `GET /version`
  - `GET /configs`
  - `PATCH /configs`
  - `GET /memory`
  - `GET /proxies`
  - `PUT /proxies/{group}`
  - `DELETE /proxies/{group}`
  - `GET /proxies/{name}/delay`
- Traffic stream:
  - `GET /traffic` via WebSocket
- Authentication:
  - HTTP requests use `Authorization: Bearer <token>`
  - WebSocket uses `?token=<token>`

Configure dae with `global.external_controller` and, if needed, `global.external_controller_secret`.

Example:

```dae
global {
  external_controller: "127.0.0.1:9090"
  external_controller_secret: "secret"
}
```

When `external_controller_secret` is set and the UI assets are available on disk, dae now also serves this dashboard at `http://<external_controller>/ui/`.
If you open the built-in page directly from dae, it will automatically use the same origin as the controller.
You can still pass the token client-side without sending it to the server logs by using a URL fragment such as `http://127.0.0.1:9090/ui/#token=secret`.

## Current Backend Limits

- The current `DaeProvider.Traffic()` implementation returns zeroed traffic values, so the UI is wired to `/traffic` but may still show flat lines until the backend starts reporting real counters.
- `/configs` currently supports patching `log-level` only. The full routing text is not exposed by the current API, so the right panel shows a JSON snapshot instead of a live routing editor.

## Run

Open `index.html` directly in a browser, or serve the directory locally:

```bash
cd ui
python3 -m http.server 4173
```

Then visit `http://localhost:4173`.
