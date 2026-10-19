# Backroom

A read-only token inspection workshop for Robinhood Chain. Paste a token contract and Backroom reads the chain, opens a case file, and says in plain words what the deployer can still do.

- Static site: `index.html`, `app.js`, `styles.css`, `logo.svg`. No build step.
- Reads only public data (chain RPC and the Blockscout explorer). Nothing is signed, no wallet is connected.
- Local preview: `node serve.mjs 3200`, then open http://localhost:3200.
