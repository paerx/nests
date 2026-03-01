# Nests

Zero‑trust local secret vault. Frontend performs encryption/decryption, backend only stores encrypted payloads and handles window workflow.

## Architecture Overview

- Frontend (browser): crypto core (HKDF + SM4 + HMAC‑SM3)
- Backend (Gin): encrypted storage + window scheduler
- Storage: local JSON files (`configs.json`, `windows.json`, `audit.log`)

## Flow

### 1) Frontend Encryption (Create/Update)
1. User enters `globalKey` (never sent to backend).
2. Frontend derives `env_key` with HKDF:
   - `env_key = HKDF_SM3(globalKey, kdf_salt, name)`
3. Frontend encrypts each key/value:
   - `e_key = SM4_CBC(env_key, key)`
   - `e_value = SM4_CBC(env_key, value)`
4. Frontend signs:
   - `sign = HMAC_SM3(env_key, JSON.stringify([{e_key, e_value}, ...]))`
5. Frontend sends encrypted data to backend:
   - `POST /api/nests/config/add` (create)
   - `POST /api/nests/config/update` (update)

### 2) Backend Storage
- Backend writes encrypted data to `data/configs.json`.
- No plaintext is stored.
- Updates are atomic (temp file + fsync + rename).
- Audit log is appended to `data/audit.log`.

### 3) Window Confirmation
1. Terminal requests a window:
   - `GET /api/nests/server/get?name=xxx`
2. Backend returns `wid` + `checker_web`.
3. User opens `checker_web` and inputs `globalKey`.
4. Frontend fetches `kdf_salt`, derives `env_key`, then submits:
   - `POST /api/nests/server/windows` with `env_key` (no globalKey).
5. Backend stores `env_key` **in memory only** for this window.

### 4) Plaintext Extraction (Internal Only)
1. Internal service calls:
   - `GET /api/nests/server/plaintext?wid=xxx`
2. Backend decrypts using in‑memory `env_key` and returns plaintext JSON.
3. Each window allows **2 reads max**.
4. After 2 reads, window is invalidated and `env_key` is cleared.

## API Summary

- `GET /api/nests/config/list`
- `GET /api/nests/config/get?name=xxx`
- `POST /api/nests/config/update`
- `POST /api/nests/config/add`
- `GET /api/nests/server/get?name=xxx`
- `POST /api/nests/server/windows` (env_key confirmation)
- `GET /api/nests/server/windows/check?wid=xxx`
- `GET /api/nests/server/plaintext?wid=xxx` (internal only)

## SDK (Go)

### Example
```go
package main

import (
    "fmt"
    "log"

    "nests/sdk"
)

func main() {
    client := sdk.Init("http://localhost:7766")
    val, err := client.GetConfig("dev", "jwt")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("jwt:", val)
}
```

Behavior:
- Prints `checker_web` URL to stdout
- Blocks and polls window status
- When ready, calls `/server/plaintext` and returns the key’s value
- Timeout/expiry exits with error

## Run Locally
## Run Locally

### Backend (API :7766)
```bash
go mod tidy
go run .
```

### Frontend (UI :7788)
```bash
cd nests
go run ./cmd/front
```

## Configuration

Backend:
- `NESTS_PORT` (default `7766`)
- `NESTS_DATA_DIR` (default `./nests/data`)
- `NESTS_CHECKER_WEB_BASE` (default `http://localhost:7788/checker`)

Frontend:
- Templates in `front/templates`
- Static assets in `front/static`

## Container Notes

If running in Docker:

1. **File paths**
   - `NESTS_DATA_DIR` must point to a writable volume (e.g. `/data`).

2. **CORS & CSP**
   - Frontend CSP currently allows `http://localhost:7766`.
   - Update CSP and API base if using different hostnames.

3. **Internal plaintext API**
   - `/api/nests/server/plaintext` is restricted to private IPs.
   - In Docker, requests may appear as bridge IPs. Ensure your container network still matches private CIDRs.

4. **Memory-only env_key**
   - `env_key` is stored in backend memory only.
   - Restarting backend clears all pending windows.

5. **Clock/time**
   - Window expiry depends on server time. Ensure container time is correct.

## Security Notes

- Backend never receives or stores `globalKey`.
- Plaintext API is limited to internal networks and max 2 reads per window.
- If you need stricter controls (token, mTLS, allowlist), add them at the gateway.
