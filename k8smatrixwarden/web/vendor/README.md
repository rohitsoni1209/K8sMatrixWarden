Vendored, not a pip dependency — the core engine stays pure stdlib. The dashboard is
self-contained (no CDN, no build step), so third-party browser JS is committed here and
served from `/vendor/...` by the same process.

- `cytoscape.min.js` — [cytoscape.js](https://js.cytoscape.org/) 3.28.1, MIT licensed,
  from `https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js`. Powers the Attack Path
  force-directed graph.
