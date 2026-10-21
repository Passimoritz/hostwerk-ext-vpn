'use strict';
/*
 * WireGuard-Schlüssel ohne "wg genkey": X25519 aus Nodes crypto, Base64 wie bei WireGuard (32 Byte → 44 Zeichen).
 * Der private Schlüssel wird nach RFC 7748 „geklemmt“ – genau wie wg genkey es tut.
 */
const crypto = require('crypto');

const B64 = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$/; // 32 Byte in Base64

const toB64 = (b64url) => Buffer.from(b64url, 'base64url').toString('base64');
const isKey = (s) => typeof s === 'string' && B64.test(s);

/** Öffentlicher Schlüssel zu einem privaten (beide Base64). */
function publicKey(privB64) {
  const d = Buffer.from(String(privB64), 'base64');
  if (d.length !== 32) throw new Error('invalid private key');
  // PKCS#8-Hülle für einen rohen X25519-Schlüssel (OID 1.3.101.110)
  const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), d]), format: 'der', type: 'pkcs8' });
  return toB64(crypto.createPublicKey(key).export({ format: 'jwk' }).x);
}

/** Neues Schlüsselpaar { privateKey, publicKey } (Base64). */
function keyPair() {
  const raw = crypto.randomBytes(32);
  raw[0] &= 248; raw[31] &= 127; raw[31] |= 64; // clamp wie wg genkey
  const privateKey = raw.toString('base64');
  return { privateKey, publicKey: publicKey(privateKey) };
}

/** Zusätzlicher gemeinsamer Schlüssel je Zugang (PresharedKey) – schützt auch gegen künftige Quantenrechner. */
const presharedKey = () => crypto.randomBytes(32).toString('base64');

module.exports = { keyPair, publicKey, presharedKey, isKey };
