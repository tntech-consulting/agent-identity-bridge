import { generateKeyPair, sign, verify, randomId } from './crypto.js';

const PROTOCOLS = ['mcp', 'a2a', 'ag-ui', 'anp'];
const TIERS = ['free', 'starter', 'pro', 'enterprise'];
const EU_RISKS = ['minimal', 'limited', 'high'];

export function createPassport({ name, protocols = ['mcp'], capabilities = [], tier = 'free', ttlDays = 365, euRisk = null }) {
  // Validation
  for (const p of protocols) {
    if (!PROTOCOLS.includes(p)) throw new Error(`Unknown protocol: ${p}. Supported: ${PROTOCOLS.join(', ')}`);
  }
  if (!TIERS.includes(tier)) throw new Error(`Unknown tier: ${tier}`);
  if (euRisk && !EU_RISKS.includes(euRisk)) throw new Error(`Unknown EU risk: ${euRisk}`);

  const keys = generateKeyPair();
  const id = randomId();
  const passportId = `urn:aib:passport:${id}`;
  const did = `did:key:z${Buffer.from(keys.publicKey, 'hex').toString('base64url')}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlDays * 86400000);

  const defaultCaps = [...protocols.map(p => `${p}:read`), ...protocols.map(p => `${p}:write`)];
  const allCaps = [...new Set([...defaultCaps, ...capabilities])];

  const passport = {
    passport_id: passportId,
    did,
    schema_version: '1.0',
    agent: {
      name,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    },
    protocols,
    capabilities: allCaps,
    tier,
    public_key: keys.publicKey,
    ...(euRisk && { eu_ai_act: { risk_level: euRisk, human_oversight: euRisk === 'high', transparency: true } }),
  };

  // Signer le passeport
  const payload = JSON.stringify(passport);
  const signature = sign(payload, keys.privateKey);
  passport.signature = signature;

  return { passport, keys: { key_id: id, ...keys } };
}

export function verifyPassport(passport) {
  const { signature, ...rest } = passport;
  if (!signature) return { valid: false, reason: 'No signature found' };

  const payload = JSON.stringify(rest);
  const isValid = verify(payload, signature, passport.public_key);

  const now = new Date();
  const expiresAt = new Date(passport.agent?.expires_at);
  const expired = expiresAt < now;

  return {
    valid: isValid && !expired,
    signature_ok: isValid,
    expired,
    expires_at: passport.agent?.expires_at,
  };
}

export function passportToVC(passport) {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'AIBPassportCredential'],
    issuer: 'did:web:aib-tech.fr',
    issuanceDate: passport.agent.created_at,
    expirationDate: passport.agent.expires_at,
    credentialSubject: {
      id: passport.did,
      passport_id: passport.passport_id,
      agent_name: passport.agent.name,
      protocols: passport.protocols,
      capabilities: passport.capabilities,
      tier: passport.tier,
    },
    proof: {
      type: 'Ed25519Signature2020',
      verificationMethod: passport.did,
      signature: passport.signature,
    },
  };
}
