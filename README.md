# Secure Messaging Project (Signal-style E2EE)

This project is an **end-to-end encrypted chat** demo inspired by Signal-style protocols. Users register cryptographic keys in the browser; messages are encrypted on the client and the **FastAPI backend** only stores **public key bundles** and **ciphertext envelopes** (it does not read message plaintext).

- **Frontend:** Next.js — UI, X3DH-style session setup, Double Ratchet messaging, demo “protocol internals” panel  
- **Backend:** FastAPI — REST API + JSON persistence under `backend/data/`

---

## Demo video

Screen recording walkthrough (download or open locally):  
[Demo of End-to-End encrypted messaging (MP4)](./assets/Demo%20of%20End%20to%20End%20encrypted%20messaging.mp4)

---

## What you need installed

| Tool | Typical version |
|------|----------------|
| **Node.js** | 20.x or newer |
| **npm** | Comes with Node |
| **Python** | 3.11+ recommended |

Check versions:

```bash
node -v
npm -v
python3 --version
```

---

## Project layout

```text
MainProject/
  README.md
  assets/
    Demo of End to End encrypted messaging.mp4   # optional walkthrough recording
  scripts/
    verify_unix.sh       # Automated checks on Unix/macOS
  backend/
    main.py              # FastAPI (run with uvicorn on port 3001)
    routes.py
    storage.py
    data/                # Created at runtime: user_keys.json, messages.json
    requirements.txt
  frontend/
    app/page.tsx         # Chat UI + protocol internals
    lib/                 # Crypto, X3DH, Double Ratchet, API client
    package.json         # Dev server uses port 4000
```

---

## Quick start (two terminals)

### Terminal 1 — Backend

From the project root:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 3001
```

Optional check:

```bash
curl -s http://127.0.0.1:3001/health
```

You should see: `{"status":"ok"}`

### Terminal 2 — Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:4000** in the browser.

The frontend calls **`/api/...`** on the same host; Next.js **rewrites** those requests to **`http://127.0.0.1:3001/...`** (see `frontend/next.config.ts`). You normally do **not** need `NEXT_PUBLIC_API_URL` for this setup.

---

## Using the app (manual demo checklist)

1. Register **two users** (e.g. separate browser profiles or normal + private window).
2. Open a chat from user A to user B and send a message (first message carries the handshake metadata).
3. On user B’s session, open the same conversation — inbound messages should show as decrypted plaintext.
4. Use the **right sidebar → Protocol internals** (collapse/expand as needed): **Show** to view session/ratchet summary; **Reveal secrets** only for demos (shows private material).
5. Optional: inspect `backend/data/user_keys.json` (public bundles) and `backend/data/messages.json` (stored ciphertext + metadata).

---

## Environment variables (optional)

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_API_URL` | Point the browser directly at the API (e.g. `http://127.0.0.1:3001`) instead of `/api` rewrites. If you do this, add your frontend origin (e.g. `http://localhost:4000`) to `allow_origins` in **`backend/main.py`** to avoid CORS errors. |

Default: leave unset and use `/api` through Next.js — simplest for local runs.

---

## Automated verification on Unix / macOS / Git Bash (Windows)

From the **project root**:

```bash
chmod +x scripts/verify_unix.sh
./scripts/verify_unix.sh
```

The script activates **`backend/.venv`**: Linux/macOS use **`.venv/bin/activate`**; Python on Windows uses **`.venv/Scripts/activate`** (already supported). It installs dependencies, briefly starts the API and runs **`curl`** smoke tests (**health**, register, bundle, send, conversation), then stops the API. It also runs **`npm ci`**, **`lint`**, **`test`**, and **`build`** in **`frontend/`**.

You need **`curl`** and **`python3`** on your PATH (Git Bash/WSL typically have both).

You can look at the backend/data the `message.json` and `user_key.json` will have been updated.

Skip the API part if port 3001 is already taken:

```bash
./scripts/verify_unix.sh --no-api
```
