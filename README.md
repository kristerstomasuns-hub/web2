# web 2 — GHOST VAULT

A private, key-gated file host. Open it in a browser and you get **404** — every path,
including `/`. Only a request to `/api/...` carrying a valid key returns anything, and a
wrong key is indistinguishable from a missing file.

## Deploy

1. Push this repo to GitHub.
2. Import it at Vercel (framework preset: **Other**, no build command needed).
3. Set environment variables (Project → Settings → Environment Variables):
   - `ACCESS_KEY` — your master key, e.g. `KEY-9FMAQ-2CPZQ-B979N-WDQQ9-89VYF`
   - `SIGNING_SECRET` *(optional)* — enables `X-Signature` on every response
   - `KEYS_JSON` *(optional, instead of ACCESS_KEY)* — `{"KEY-AAA...":"loader","KEY-BBB...":"me"}`
4. Deploy. Done.

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/api/verify` | `{ "ok": true, "label": "env" }` |
| GET | `/api/list` | `{ "files": [ { "name", "size" } ] }` |
| GET | `/api/file/<name>` | the file's raw contents |

Auth: `Authorization: Bearer <key>` or `X-Api-Key: <key>`.

Everything else — `/`, `/files/pinreta.lua`, a static path, a bad key — returns the same
`404 Not Found`.

## Adding files

Files live in `files/` and are served **only** through the API. Vercel's filesystem is
read-only, so there is no upload endpoint: you add a file by committing it here and letting
it deploy. That is also what keeps it safe — `files/` is not under `public/`, so it is
never served statically and cannot be fetched without the key.

```bash
git add files/myscript.lua
git commit -m "add myscript.lua"
git push
```

## Loader

```lua
local BASE = "https://your-project.vercel.app"
local KEY  = "KEY-..."

local function fetch(name)
    local ok, body = pcall(function()
        return game:HttpGet(BASE .. "/api/file/" .. name, true, { Authorization = "Bearer " .. KEY })
    end)
    if not ok or not body or body:find("Not Found", 1, true) then return nil end
    return body
end

-- optional: verify the key before pulling anything
local ping = game:HttpGet(BASE .. "/api/verify", true, { Authorization = "Bearer " .. KEY })
if not ping:find('"ok":true', 1, true) then warn("key rejected") return end

local src = fetch("pinreta.lua")
if not src then warn("pull failed") return end
loadstring(src)()
```

If you set `SIGNING_SECRET`, return it via the 4th argument of `request`/`HttpGet` (executor
dependent) or use `syn.request` and check `X-Signature` against
`sha256 = HMAC_SHA256(body, SIGNING_SECRET)` before running anything.

## Notes

- Keys are compared in constant time, so a wrong key cannot be guessed a character at a time.
- File names are a single segment from `[A-Za-z0-9._-]`; `..`, slashes, leading dots and
  other extensions are rejected outright.
- `X-Robots-Tag: noindex` is set so search engines do not index the host.
