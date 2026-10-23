# EasyJWT

A self-hosted web UI for ticarpi's jwt_tool. Paste a token, decode it, crack its secret, inject or forge claims, and run known JWT vulnerability exploits, all from a browser page.

**Live instance:** [easyjwt.imegz.dev](https://easyjwt.imegz.dev/)
**Source:** [github.com/iMegz/EasyJWT](https://github.com/iMegz/EasyJWT)

You can use the hosted instance above directly, no install needed, or run it yourself locally with the steps below.

## Warning

This toolkit is for legal use only: your own applications, CTFs, authorized labs, and engagements where you have explicit permission to test. Do not point it at systems you don't own or don't have written authorization to test. You're responsible for how you use it.

## What's included

- `Dockerfile`, builds the web UI on top of the jwt_tool image. It also compiles gmpy2 and the crypto library from source, those have no prebuilt wheel for this base image, so the very first build takes a few minutes longer than later ones.
- `docker-compose.yml`, for local use: starts the image with the wordlists folder and a persistent config volume mounted.
- `webui/`, the Flask app, HTML, CSS and JS.
- `wordlists/`, the built-in wordlist(s) used automatically for cracking. These are baked into the image and never listed or shown to users of the web UI, they just see "Built-in wordlist" as a label in the results.
- `start.bat` / `shutdown.bat`, Windows helpers so anyone who clones this repo can run it locally with a double click instead of typing Docker commands. `setup.bat` still exists and just runs `start.bat` for anyone used to the old two-step flow.

## Running locally (Windows + Docker Desktop)

1. Double click `start.bat`. Every time, it checks Docker is running, pulls the latest code if this is a git checkout, rebuilds the image (usually quick, except the very first build), starts the container, and opens `http://localhost:5000` in your browser. No separate setup step, and no way to end up running a stale image.
2. Double click `shutdown.bat` when done, it stops the container without removing it.

Locally the web UI only binds to `127.0.0.1`, so it's reachable from your own machine only. To reach it from another device on your network, change the port mapping in `docker-compose.yml` to bind `0.0.0.0` instead.

## Running locally (any OS, without the .bat files)

```
git pull
docker compose build
docker compose up -d
```

Then open `http://localhost:5000`. Stop it with `docker compose stop`. Since `webui/` and `wordlists/` are baked into the image with `COPY` rather than mounted, rerun `docker compose build` after pulling or editing code, `docker compose up -d` alone reuses whatever was last built.

## The four tabs

- **Decode**, view a token's header and payload.
- **Crack**, two ways to recover key material:
  - Secret cracking against a wordlist, for HS256/HS384/HS512 tokens. Runs against the built-in wordlist automatically, or optionally upload your own `.txt` wordlist (2 MB max) for that run, it's used in memory and never stored or exposed, and the built-in list's contents are never shown.
  - Public key recovery from two tokens, for RS256/RS384/RS512 tokens signed with the same key, when the target's public key isn't exposed anywhere (no JWKS, no cert). The key size is detected automatically from the signatures, no guessing involved. This does a real factorization step and can take anywhere from about 20 seconds (1024-bit key) to a couple of minutes (4096-bit key), with a live elapsed-time and estimate shown while it runs. The server can only handle one request at a time while this is running, so avoid using other features here until it finishes. A "Use in Key confusion" button sends the recovered key straight into the Key confusion exploit below.
- **Forge**, inject or update a header or payload claim, then optionally sign the result with a secret (HMAC) or a private key (RSA/EC/PSS).
- **Exploits**, run both native checks and jwt_tool's own exploits:
  - alg:none, with an option to also try case variants (`None`, `NONE`, etc.).
  - Null signature.
  - Blank password accepted.
  - Psychic signature, an ECDSA (ES256/384/512) implementation bug where a zero-value signature component verifies against any payload for some flawed verifiers.
  - Key confusion, needs a target public key. You can paste a PEM directly, paste a URL and click Convert to PEM to fetch and convert it, or use the key recovered in the Crack tab above.
  - Inline JWKS injection.
  - Spoof JWKS, serves a `jwks.json` with your own forged key under a `kid` you choose, then points a token's `jku` at it. The `kid` can be left as the token's own, set to a value you type, or pulled from the current JWKS. The default `jku` points at wherever you're actually running this from (your own `http://localhost:5000/jwks.json` locally, or `https://easyjwt.imegz.dev/jwks.json` on the hosted instance), so this works without any internet access by default. It only reaches the network if you type a different URL yourself.
  - kid header path traversal, tries directory-traversal payloads in the `kid` header against common key-file locations.

## Running fully offline

Decoding, forging, cracking, and public-key recovery never touch the network. Within Exploits, Key confusion's URL-fetch and Spoof JWKS's kid auto-fetch are the only features that make an outbound request, and only if you give them a URL. Spoof JWKS's default URL no longer points at the public hosted site, it's derived from whatever address you're actually using to reach the app, so a stock local run stays offline unless you choose otherwise.

## Configuration

All of these are optional environment variables, set in `docker-compose.yml` or your shell before running the container.

- `AUTH_USER` / `AUTH_PASS`, set both to require HTTP Basic Auth for the whole app. Unset by default, meaning anyone who can reach the port can use it. Recommended if you expose this beyond your own machine.
- `SITE_URL`, overrides the canonical URL used as the Spoof JWKS default `jku`. Leave unset for local or LAN use, it's derived from the request itself; set it if you're behind a proxy that doesn't forward the real host, or to force the public domain.
- `RATE_LIMIT_SECONDS`, minimum seconds between calls to rate-limited endpoints. Defaults to `3`.
- `PORT`, port the app listens on inside the container. Defaults to `5000`.

## Updating the built-in wordlist

Edit or replace the `.txt` files in `wordlists/`. All `.txt` files in that folder are merged and deduplicated automatically at crack time.

## Notes

The web UI runs jwt_tool's own Python code under the hood for secret cracking and most exploits (null signature, blank password, psychic signature, key confusion, inline JWKS injection); alg:none, Spoof JWKS, and kid path traversal are built natively in this app instead. If jwt_tool's command line flags change in a future version, the delegated parts of the Forge and Exploits tabs may need matching updates in `webui/app.py`.

---

Built by [Ahmed Magdi Mostafa, Full-Stack Developer](https://imegz.dev/)
