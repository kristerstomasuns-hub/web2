/**
 * GHOST VAULT - key-gated file store, Vercel serverless build.
 *
 * One catch-all function rather than a file per route, so the whole surface is this file
 * plus vercel.json.
 *
 *   GET  /api/verify          -> { ok, label }                key check
 *   GET  /api/list            -> { files: [ { name, size } ] }
 *   GET  /api/file/<name>     -> raw bytes
 *
 * Anyone opening the site normally gets a 404 -- including "/" -- because nothing is ever
 * served unless the path starts with /api and carries a valid key. A wrong key and a
 * missing file return the SAME 404, so nothing reveals whether a file exists.
 *
 * DIFFERENCE FROM THE NODE BUILD, and it matters: Vercel's filesystem is READ-ONLY. There
 * is no PUT/DELETE here, because a serverless function cannot persist a write. Files are
 * added the way GitHub adds files -- commit them to the repository and let it deploy. The
 * `files/` folder is deliberately NOT under public/, so it is never statically served and
 * cannot be fetched without the key.
 *
 * Environment variables:
 *   ACCESS_KEY      the master key (or point KEYS_JSON at a JSON string of key->label)
 *   SIGNING_SECRET  optional; when set, responses carry X-Signature: sha256=<hmac>
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Bundled with the function via vercel.json's includeFiles.
const FILES_DIR = path.join(process.cwd(), 'files');
const MAX_BYTES = Number(process.env.MAX_BYTES || 32 * 1024 * 1024);

function loadKeys() {
    const keys = new Map();
    // A JSON map first, so several named keys can be revoked independently.
    if (process.env.KEYS_JSON) {
        try {
            const raw = process.env.KEYS_JSON.replace(/^\uFEFF/, '');
            for (const [key, label] of Object.entries(JSON.parse(raw))) {
                if (typeof key === 'string' && key.length >= 8) {
                    keys.set(key, typeof label === 'string' ? label : 'unnamed');
                }
            }
        } catch (err) {
            console.error('[vault] KEYS_JSON is not valid JSON:', err.message);
        }
    }
    if (keys.size === 0 && process.env.ACCESS_KEY) keys.set(process.env.ACCESS_KEY, 'env');
    return keys;
}

const KEYS = loadKeys();

function keyLabelFor(req) {
    const header = String(req.headers.authorization || '');
    let presented = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : '';
    if (!presented) presented = String(req.headers['x-api-key'] || '').trim();
    if (!presented) return null;
    const given = Buffer.from(presented);
    let match = null;
    for (const [key, label] of KEYS) {
        const expected = Buffer.from(key);
        // timingSafeEqual throws on a length mismatch, so lengths are compared first.
        if (expected.length === given.length && crypto.timingSafeEqual(expected, given)) match = label;
    }
    return match;
}

function send(res, status, body, type) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    const headers = {
        'Content-Type': type || 'application/json',
        'Content-Length': buf.length,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    };
    if (process.env.SIGNING_SECRET) {
        headers['X-Signature'] = 'sha256=' + crypto
            .createHmac('sha256', process.env.SIGNING_SECRET)
            .update(buf)
            .digest('hex');
    }
    res.writeHead(status, headers);
    res.end(buf);
}

/** One failure response for everything: bad key, unknown file, malformed path. */
function notFound(res) {
    send(res, 404, 'Not Found', 'text/plain');
}

function safeName(raw) {
    let name = String(raw || '').trim();
    try {
        name = decodeURIComponent(name);
    } catch {
        return null;
    }
    if (!name || name.length > 128) return null;
    if (name.includes('/') || name.includes('\\') || name.includes('..')) return null;
    if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;
    if (name.startsWith('.')) return null;
    return name;
}

function listFiles() {
    try {
        return fs.readdirSync(FILES_DIR)
            .filter((n) => {
                try {
                    return fs.statSync(path.join(FILES_DIR, n)).isFile();
                } catch {
                    return false;
                }
            })
            .map((n) => ({ name: n, size: fs.statSync(path.join(FILES_DIR, n)).size }));
    } catch {
        return [];
    }
}

module.exports = (req, res) => {
    // Vercel gives the path as a query param on a catch-all route; fall back to req.url.
    let segments = [];
    if (req.query && req.query.path) {
        segments = Array.isArray(req.query.path) ? req.query.path : [req.query.path];
    } else {
        try {
            segments = new URL(req.url, 'http://localhost').pathname.split('/').filter(Boolean);
            if (segments[0] === 'api') segments = segments.slice(1);
        } catch {
            return notFound(res);
        }
    }

    // Anything that is not an authenticated /api call is a 404.
    if (segments.length < 1) return notFound(res);
    const label = keyLabelFor(req);
    if (!label) return notFound(res);

    const action = segments[0];

    try {
        if (action === 'verify') {
            return send(res, 200, JSON.stringify({ ok: true, label }));
        }

        if (action === 'list') {
            return send(res, 200, JSON.stringify({ files: listFiles() }));
        }

        if (action === 'file' && segments.length === 2) {
            const name = safeName(segments[1]);
            if (!name) return notFound(res);
            const full = path.join(FILES_DIR, name);
            if (!full.startsWith(FILES_DIR + path.sep)) return notFound(res);
            if (!fs.existsSync(full)) return notFound(res);
            const stat = fs.statSync(full);
            if (stat.size > MAX_BYTES) return notFound(res);
            return send(res, 200, fs.readFileSync(full), 'text/plain; charset=utf-8');
        }
    } catch (err) {
        // Never leak internals: the caller sees the same 404 as everything else.
        console.error('[vault]', err.message);
        return notFound(res);
    }

    return notFound(res);
};
