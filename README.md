# EasyJWT

A self-hosted web UI for ticarpi's jwt_tool. Paste a token, decode it, crack its secret, inject or forge claims, and run known JWT vulnerability exploits, all from a browser page.

**Live instance:** [easyjwt.imegz.dev](https://easyjwt.imegz.dev/)
**Source:** [github.com/iMegz/EasyJWT](https://github.com/iMegz/EasyJWT)

You can use the hosted instance above directly, no install needed, or run it yourself locally with the steps below.

## Warning

This toolkit is for legal use only: your own applications, CTFs, authorized labs, and engagements where you have explicit permission to test. Do not point it at systems you don't own or don't have written authorization to test. You're responsible for how you use it.

## What's included

- `Dockerfile`, builds the web UI on top of the jwt_tool image.
- `docker-compose.yml`, for local use: starts the image with the wordlists folder and a persistent config volume mounted.
- `webui/`, the Flask app, HTML, CSS and JS.
- `wordlists/`, the built-in wordlist(s) used automatically for cracking. These are baked into the image and never listed or shown to users of the web UI, they just see "Built-in wordlist" as a label in the results.
- `setup.bat` / `start.bat` / `shutdown.bat`, Windows helpers so anyone who clones this repo can run it locally with a double click instead of typing Docker commands.

## Running locally (Windows + Docker Desktop)

1. Double click `setup.bat`, it checks Docker, builds the image, and makes sure the wordlists folder exists.
2. Double click `start.bat`, it starts the container and opens `http://localhost:5000` in your browser.
3. Double click `shutdown.bat` when done, it stops the container without removing it.

Locally the web UI only binds to `127.0.0.1`, so it's reachable from your own machine only.

## Running locally (any OS, without the .bat files)

```
docker compose build
docker compose up -d
```

Then open `http://localhost:5000`. Stop it with `docker compose stop`.

## The four tabs

- **Decode**, view a token's header and payload.
- **Crack**, runs against the built-in wordlist automatically. You can optionally upload your own `.txt` wordlist (2 MB max) for that run, it's used in memory and never stored or exposed, and the built-in list's contents are never shown.
- **Forge**, inject or update a header or payload claim, then optionally sign the result with a secret (HMAC) or a private key (RSA/EC/PSS).
- **Exploits**, run jwt_tool's built-in exploits: alg:none, null signature, blank password, psychic ECDSA signature, key confusion, inline JWKS injection, and JWKS spoofing. Note that the Spoof JWKS option makes the server fetch a URL you supply, that's inherent to what the exploit does.

## Updating the built-in wordlist

Edit or replace the `.txt` files in `wordlists/`. All `.txt` files in that folder are merged and deduplicated automatically at crack time.

## Notes

The web UI runs jwt_tool's own Python code under the hood, it's a thin wrapper, not a reimplementation. If jwt_tool's command line flags change in a future version, the Forge and Exploits tabs may need matching updates in `webui/app.py`.

---

Built by [Ahmed Magdi Mostafa, Full-Stack Developer](https://imegz.dev/)
