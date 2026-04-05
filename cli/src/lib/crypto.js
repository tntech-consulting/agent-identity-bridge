import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from 'crypto';

// noble/ed25519 v2 requires sha512 sync
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export function generateKeyPair() {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = ed.getPublicKey(privKey);
  return {
    privateKey: Buffer.from(privKey).toString('hex'),
    publicKey: Buffer.from(pubKey).toString('hex'),
  };
}

export function sign(message, privateKeyHex) {
  const privKey = Buffer.from(privateKeyHex, 'hex');
  const msgBytes = typeof message === 'string'
    ? new TextEncoder().encode(message)
    : message;
  const sig = ed.sign(msgBytes, privKey);
  return Buffer.from(sig).toString('hex');
}

export function verify(message, signatureHex, publicKeyHex) {
  try {
    const pubKey = Buffer.from(publicKeyHex, 'hex');
    const sig = Buffer.from(signatureHex, 'hex');
    const msgBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;
    return ed.verify(sig, msgBytes, pubKey);
  } catch {
    return false;
  }
}

export function randomId() {
  return randomBytes(12).toString('hex');
}
