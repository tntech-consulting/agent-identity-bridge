import { execSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync, rmSync } from 'fs';
import { ok } from 'assert';

let passed = 0;
let failed = 0;
const errors = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}`);
    console.log(`     ${e.message}`);
    failed++;
    errors.push({ name, error: e.message });
  }
}

function run(cmd) {
  try {
    return { stdout: execSync(cmd, { encoding: 'utf8', cwd: '/home/claude/aib-cli' }), code: 0 };
  } catch (e) {
    return { stdout: e.stdout || '', stderr: e.stderr || '', code: e.status };
  }
}

// Cleanup
if (existsSync('/home/claude/aib-cli/.aib')) {
  rmSync('/home/claude/aib-cli/.aib', { recursive: true });
}

console.log('\n── AUDIT CLI @aib-protocol/cli v0.1.0 ──\n');

// ─── SECTION 1 : PASSPORT ───
console.log('📋 Section 1 — Passport\n');

test('passport create basique génère passport.json + keys.json', () => {
  const r = run('node bin/aib.js passport create --name "audit-agent" --protocols mcp');
  ok(r.code === 0, `Exit code ${r.code}\n${r.stdout}`);
  ok(existsSync('/home/claude/aib-cli/.aib/passport.json'), 'passport.json absent');
  ok(existsSync('/home/claude/aib-cli/.aib/keys.json'), 'keys.json absent');
});

test('passport.json — champs obligatoires présents', () => {
  const p = JSON.parse(readFileSync('/home/claude/aib-cli/.aib/passport.json', 'utf8'));
  ok(p.passport_id?.startsWith('urn:aib:passport:'), `passport_id: ${p.passport_id}`);
  ok(p.did?.startsWith('did:key:'), `did: ${p.did}`);
  ok(p.signature, 'signature absente');
  ok(p.public_key?.match(/^[0-9a-f]{64}$/), `public_key invalide: ${p.public_key?.slice(0,16)}`);
  ok(p.agent?.name === 'audit-agent', `agent.name: ${p.agent?.name}`);
  ok(p.protocols?.includes('mcp'), 'protocols mcp absent');
  ok(Array.isArray(p.capabilities) && p.capabilities.length > 0, 'capabilities vide');
  ok(p.agent?.expires_at, 'expires_at absent');
  ok(p.agent?.created_at, 'created_at absent');
  ok(p.schema_version === '1.0', `schema_version: ${p.schema_version}`);
});

test('keys.json — privateKey + publicKey hex 64 chars', () => {
  const k = JSON.parse(readFileSync('/home/claude/aib-cli/.aib/keys.json', 'utf8'));
  ok(k.privateKey?.match(/^[0-9a-f]{64}$/), `privateKey invalide`);
  ok(k.publicKey?.match(/^[0-9a-f]{64}$/), `publicKey invalide`);
  ok(k.key_id, 'key_id absent');
});

test('passport create multi-protocoles mcp,a2a,ag-ui', () => {
  const r = run('node bin/aib.js passport create --name "multi" --protocols mcp,a2a,ag-ui --output /tmp/aib-multi');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const p = JSON.parse(readFileSync('/tmp/aib-multi/passport.json', 'utf8'));
  ok(['mcp','a2a','ag-ui'].every(p2 => p.protocols.includes(p2)), `protocols: ${p.protocols}`);
  ok(p.capabilities.length >= 6, `capabilities attendues >= 6, got ${p.capabilities.length}`);
  rmSync('/tmp/aib-multi', { recursive: true });
});

test('passport create avec EU AI Act risk=high', () => {
  const r = run('node bin/aib.js passport create --name "eu-agent" --eu-risk high --output /tmp/aib-eu');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const p = JSON.parse(readFileSync('/tmp/aib-eu/passport.json', 'utf8'));
  ok(p.eu_ai_act?.risk_level === 'high', `risk_level: ${p.eu_ai_act?.risk_level}`);
  ok(p.eu_ai_act?.human_oversight === true, 'human_oversight doit être true pour high');
  ok(p.eu_ai_act?.transparency === true, 'transparency doit être true');
  rmSync('/tmp/aib-eu', { recursive: true });
});

test('passport create protocole inconnu → exit 1', () => {
  const r = run('node bin/aib.js passport create --name "x" --protocols foobar');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('passport create tier invalide → exit 1', () => {
  const r = run('node bin/aib.js passport create --name "x" --tier superpro');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('passport create eu-risk invalide → exit 1', () => {
  const r = run('node bin/aib.js passport create --name "x" --eu-risk extreme');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('passport verify — passeport valide → exit 0', () => {
  const r = run('node bin/aib.js passport verify');
  ok(r.code === 0, `Exit code: ${r.code}\n${r.stdout}`);
  ok(r.stdout.includes('VALID'), 'VALID attendu dans stdout');
  ok(r.stdout.includes('Signature OK'), 'Signature OK attendu');
});

test('passport verify — fichier inexistant → exit 1', () => {
  const r = run('node bin/aib.js passport verify --file /tmp/nonexistent-xyz.json');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('passport verify — passeport falsifié → INVALID', () => {
  const p = JSON.parse(readFileSync('/home/claude/aib-cli/.aib/passport.json', 'utf8'));
  p.agent.name = 'HACKED';
  writeFileSync('/tmp/fake-passport.json', JSON.stringify(p));
  const r = run('node bin/aib.js passport verify --file /tmp/fake-passport.json');
  ok(r.code !== 0 || r.stdout.includes('INVALID'), 'Devrait détecter la falsification');
  unlinkSync('/tmp/fake-passport.json');
});

test('passport export — credential.json W3C valide', () => {
  const r = run('node bin/aib.js passport export');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const vc = JSON.parse(readFileSync('/home/claude/aib-cli/.aib/credential.json', 'utf8'));
  ok(vc['@context']?.includes('https://www.w3.org/2018/credentials/v1'), '@context W3C absent');
  ok(vc.type?.includes('VerifiableCredential'), 'type VC absent');
  ok(vc.type?.includes('AIBPassportCredential'), 'type AIBPassportCredential absent');
  ok(vc.proof?.type === 'Ed25519Signature2020', `proof.type: ${vc.proof?.type}`);
  ok(vc.credentialSubject?.id?.startsWith('did:key:'), 'credentialSubject.id invalide');
  ok(vc.issuanceDate, 'issuanceDate absent');
  ok(vc.expirationDate, 'expirationDate absent');
});

// ─── SECTION 2 : GUARD ───
console.log('\n🛡️  Section 2 — Guard\n');

const ALLOW_CASES = [
  ['data.read', '{}'],
  ['file.list', '{"path":"/home"}'],
  ['api.call', '{"endpoint":"https://api.example.com"}'],
  ['memory.store', '{"key":"value"}'],
  ['log.write', '{"message":"hello"}'],
];

const DENY_CASES = [
  ['exec', '{"command":"rm -rf /"}', 'rm -rf'],
  ['exec', '{"command":"sudo rm -rf /etc"}', 'sudo rm'],
  ['db',   '{"query":"DROP TABLE users"}', 'DROP TABLE'],
  ['db',   '{"query":"DELETE FROM passports"}', 'DELETE FROM'],
  ['sys',  '{"action":"shutdown now"}', 'shutdown'],
  ['sys',  '{"action":"reboot"}', 'reboot'],
  ['fs',   '{"cmd":"mkfs /dev/sda"}', 'mkfs'],
  ['fs',   '{"cmd":"chmod 777 /etc/passwd"}', 'chmod 777'],
  ['fork', '{"cmd":":(){:|:&};:"}', ':(){:|:&};:'],
];

ALLOW_CASES.forEach(([action, params]) => {
  test(`guard ALLOW: ${action}`, () => {
    const r = run(`node bin/aib.js guard check --action "${action}" --params '${params}'`);
    ok(r.code === 0, `Devrait ALLOW (exit 0), got ${r.code}\n${r.stdout}`);
    ok(r.stdout.includes('ALLOW'), `ALLOW attendu dans stdout, got: ${r.stdout.slice(0,100)}`);
  });
});

DENY_CASES.forEach(([action, params, pattern]) => {
  test(`guard DENY: ${pattern}`, () => {
    const r = run(`node bin/aib.js guard check --action "${action}" --params '${params}'`);
    ok(r.code === 1, `Devrait DENY (exit 1), got ${r.code}\n${r.stdout}`);
    ok(r.stdout.includes('DENY'), `DENY attendu dans stdout`);
    ok(r.stdout.toLowerCase().includes(pattern.toLowerCase().slice(0,8)), `Pattern "${pattern}" absent du message`);
  });
});

test('guard params JSON invalide → exit 1', () => {
  const r = run("node bin/aib.js guard check --action test --params 'not-json'");
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('guard action manquante → exit non-zero', () => {
  const r = run("node bin/aib.js guard check");
  ok(r.code !== 0, `Devrait échouer sans --action`);
});

// ─── SECTION 3 : POLICY ───
console.log('\n📜 Section 3 — Policy\n');

test('policy list — 5 templates présents', () => {
  const r = run('node bin/aib.js policy list');
  ok(r.code === 0, `Exit code: ${r.code}`);
  ['eu-ai-act','minimal-guardrails','separation-of-duties','budget-control','delegation-chain'].forEach(t => {
    ok(r.stdout.includes(t), `Template "${t}" absent`);
  });
});

test('policy show eu-ai-act — nom + règles présents', () => {
  const r = run('node bin/aib.js policy show --template eu-ai-act');
  ok(r.code === 0, `Exit code: ${r.code}`);
  ok(r.stdout.includes('EU AI Act'), 'Nom du template absent');
  ok(r.stdout.includes('eu-risk-declaration') || r.stdout.includes('Rules'), 'Règles absentes');
});

test('policy show template inexistant → exit 1', () => {
  const r = run('node bin/aib.js policy show --template nonexistent-xyz');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('policy evaluate ALLOW — action neutre', () => {
  const r = run("node bin/aib.js policy evaluate --action data.read --params '{}'");
  ok(r.code === 0, `Devrait ALLOW, got ${r.code}\n${r.stdout}`);
  ok(r.stdout.includes('ALLOW'), 'ALLOW attendu');
});

test('policy evaluate DENY — budget dépassé (500 > 100)', () => {
  const r = run("node bin/aib.js policy evaluate --action payment --params '{\"cost_eur\":500}' --policy budget-control");
  ok(r.code === 1, `Devrait DENY, got ${r.code}`);
  ok(r.stdout.includes('DENY'), 'DENY attendu');
  ok(r.stdout.includes('500'), 'Montant 500 attendu dans message');
});

test('policy evaluate ALLOW — budget OK (50 < 100)', () => {
  const r = run("node bin/aib.js policy evaluate --action payment --params '{\"cost_eur\":50}' --policy budget-control");
  ok(r.code === 0, `Devrait ALLOW, got ${r.code}`);
});

test('policy evaluate DENY — pattern dangereux eu-ai-act', () => {
  const r = run("node bin/aib.js policy evaluate --action data.export.personal --params '{}' --policy eu-ai-act");
  ok(r.code === 1, `Devrait DENY, got ${r.code}`);
});

// ─── SECTION 4 : TRANSLATE ───
console.log('\n🔄 Section 4 — Translate\n');

test('translate protocols — liste mcp a2a ag-ui', () => {
  const r = run('node bin/aib.js translate protocols');
  ok(r.code === 0, `Exit code: ${r.code}`);
  ['mcp','a2a','ag-ui'].forEach(p => ok(r.stdout.includes(p), `${p} absent`));
});

test('translate to a2a — agent_card + did + skills valides', () => {
  const r = run('node bin/aib.js translate to --protocol a2a');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const lines = r.stdout.split('\n');
  const jsonStart = lines.findIndex(l => l.trim().startsWith('{'));
  const json = JSON.parse(lines.slice(jsonStart).join('\n'));
  ok(json.schema === 'a2a/1.0', `schema: ${json.schema}`);
  ok(json.agent_card?.did?.startsWith('did:key:'), `did: ${json.agent_card?.did}`);
  ok(Array.isArray(json.agent_card?.skills) && json.agent_card.skills.length > 0, 'skills vide');
  ok(json.agent_card?.authentication?.type === 'Ed25519', `auth type: ${json.agent_card?.authentication?.type}`);
  ok(json.aib_passport_id?.startsWith('urn:aib:passport:'), `passport_id: ${json.aib_passport_id}`);
});

test('translate to mcp — server_info + tools valides', () => {
  const r = run('node bin/aib.js translate to --protocol mcp --from a2a');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const lines = r.stdout.split('\n');
  const jsonStart = lines.findIndex(l => l.trim().startsWith('{'));
  const json = JSON.parse(lines.slice(jsonStart).join('\n'));
  ok(json.schema === 'mcp/1.0', `schema: ${json.schema}`);
  ok(Array.isArray(json.tools) && json.tools.length > 0, 'tools vide');
  ok(json.tools[0].inputSchema?.type === 'object', 'inputSchema invalide');
  ok(json.aib_passport?.signature, 'signature absente');
});

test('translate to ag-ui — manifest + actions valides', () => {
  const r = run('node bin/aib.js translate to --protocol ag-ui');
  ok(r.code === 0, `Exit code: ${r.code}`);
  const lines = r.stdout.split('\n');
  const jsonStart = lines.findIndex(l => l.trim().startsWith('{'));
  const json = JSON.parse(lines.slice(jsonStart).join('\n'));
  ok(json.schema === 'ag-ui/1.0', `schema: ${json.schema}`);
  ok(Array.isArray(json.manifest?.actions) && json.manifest.actions.length > 0, 'actions vide');
  ok(json.manifest?.identity?.did?.startsWith('did:key:'), 'identity.did invalide');
});

test('translate même protocole (mcp→mcp) — note renvoyée', () => {
  const r = run('node bin/aib.js translate to --protocol mcp --from mcp');
  ok(r.code === 0, `Exit code: ${r.code}`);
  ok(r.stdout.includes('Same protocol') || r.stdout.includes('mcp'), 'Réponse attendue');
});

test('translate protocole inconnu → exit 1', () => {
  const r = run('node bin/aib.js translate to --protocol foobar');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

test('translate fichier passport inexistant → exit 1', () => {
  const r = run('node bin/aib.js translate to --protocol a2a --file /tmp/nonexistent-xyz.json');
  ok(r.code === 1, `Devrait exit 1, got ${r.code}`);
});

// ─── RÉSUMÉ ───
console.log('\n── Résumé final ──\n');
console.log(`  Total  : ${passed + failed}`);
console.log(`  ✅ OK  : ${passed}`);
console.log(`  ❌ KO  : ${failed}`);
if (errors.length > 0) {
  console.log('\n  Échecs:');
  errors.forEach(e => console.log(`    ✗ ${e.name}\n      → ${e.error}`));
}
console.log('');
process.exit(failed > 0 ? 1 : 0);
