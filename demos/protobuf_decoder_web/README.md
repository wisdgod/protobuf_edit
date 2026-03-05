# protobuf-decoder-web (demo)

## Dev

```bash
cd demos/protobuf_decoder_web && trunk serve
```

## Release build

```bash
cd demos/protobuf_decoder_web && trunk build --release
```

The output is written to `demos/protobuf_decoder_web/dist/` (not tracked by git).

## Minify `dist/`

Trunk already produces a compact `dist/index.html` with Subresource Integrity (SRI) attributes.
If you rewrite any files in `dist/` (JS/CSS/wasm), you must also update the corresponding
`integrity=sha384-...` attributes in `dist/index.html`, otherwise browsers will refuse to load
the resources.

This repo includes a small minifier wrapper that:
- Minifies `dist/*.js` and `dist/*.css` (only if it reduces size).
- Optionally runs `wasm-opt -Oz` for `dist/*.wasm`.
- Recomputes SRI hashes and updates `dist/index.html`.

Run:

```bash
cd demos/protobuf_decoder_web && bash scripts/minify_dist.sh
```

To also optimize wasm (requires `wasm-opt`):

```bash
cd demos/protobuf_decoder_web && bash scripts/minify_dist.sh --wasm-opt
```

The first run installs a tiny local tool (`tools/minify_dist/`) via `npm ci` (dependency: `esbuild`).
