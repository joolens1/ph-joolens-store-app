const crypto = require("crypto");
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * Normalize the request path used for signing.
 * Query strings are preserved, while trailing path slashes are removed.
 */
function canonicalizePath(path) {
  let value = String(path ?? "/").trim();
  if (!value.startsWith("/")) value = "/" + value;

  const queryIndex = value.indexOf("?");
  const pathname = queryIndex === -1 ? value : value.slice(0, queryIndex);
  const query = queryIndex === -1 ? "" : value.slice(queryIndex);
  const normalizedPathname = pathname === "/" ? "/" : pathname.replace(/\/+$/, "");

  return (normalizedPathname || "/") + query;
}

/**
 * Keep an already serialized body byte-for-byte stable. Objects are serialized
 * compactly so the exact string sent over the wire can be reused for signing.
 */
function serializeBody(body) {
  if (body === undefined || body === null) return "";
  return typeof body === "string" ? body : JSON.stringify(body);
}

/**
 * Build the exact string required by the Gift API:
 * timestamp + method + path + body
 */
function buildSignaturePayload({ timestamp, method, path, body }) {
  return [
    String(timestamp).trim(),
    String(method).trim().toUpperCase(),
    canonicalizePath(path),
    serializeBody(body),
  ].join("");
}

function buildGiftSignature({ timestamp, method, path, body }) {
  const accessToken = process.env.GIFT_ACCESS_TOKEN;
  if (!accessToken) {
    throw new Error("GIFT_ACCESS_TOKEN is not configured");
  }

  const payload = buildSignaturePayload({ timestamp, method, path, body });
  return crypto.createHmac("sha256", accessToken).update(payload, "utf8").digest("hex");
}

function buildGiftAuthHeaders({ timestamp, method, path, body }) {
  const normalizedTimestamp = String(timestamp).trim();
  return {
    "X-Gift-Timestamp": normalizedTimestamp,
    "X-Gift-Signature": buildGiftSignature({ timestamp: normalizedTimestamp, method, path, body }),
  };
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

module.exports = {
  app,
  canonicalizePath,
  serializeBody,
  buildSignaturePayload,
  buildGiftSignature,
  buildGiftAuthHeaders,
};
