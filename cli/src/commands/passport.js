import { Command } from 'commander';
import chalk from 'chalk';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { createPassport, verifyPassport, passportToVC } from '../lib/passport.js';

export function passportCommand() {
  const cmd = new Command('passport').description('Manage agent passports');

  cmd.command('create')
    .description('Create a new agent passport with Ed25519 keypair')
    .requiredOption('--name <name>', 'Agent name')
    .option('--protocols <protocols>', 'Comma-separated protocols (mcp,a2a,ag-ui,anp)', 'mcp')
    .option('--capabilities <caps>', 'Comma-separated custom capabilities', '')
    .option('--tier <tier>', 'Tier: free|starter|pro|enterprise', 'free')
    .option('--ttl <days>', 'Time-to-live in days', '365')
    .option('--eu-risk <level>', 'EU AI Act risk: minimal|limited|high')
    .option('--output <dir>', 'Output directory', './.aib')
    .action((opts) => {
      try {
        const { passport, keys } = createPassport({
          name: opts.name,
          protocols: opts.protocols.split(',').map(p => p.trim()),
          capabilities: opts.capabilities ? opts.capabilities.split(',').map(c => c.trim()).filter(Boolean) : [],
          tier: opts.tier,
          ttlDays: parseInt(opts.ttl),
          euRisk: opts.euRisk || null,
        });

        mkdirSync(opts.output, { recursive: true });
        writeFileSync(`${opts.output}/passport.json`, JSON.stringify(passport, null, 2));
        writeFileSync(`${opts.output}/keys.json`, JSON.stringify(keys, null, 2));

        console.log(chalk.green('\n✅ Passport created successfully\n'));
        console.log(chalk.cyan('  Passport ID  :'), passport.passport_id);
        console.log(chalk.cyan('  DID          :'), passport.did);
        console.log(chalk.cyan('  Agent        :'), passport.agent.name);
        console.log(chalk.cyan('  Protocols    :'), passport.protocols.join(', '));
        console.log(chalk.cyan('  Capabilities :'), passport.capabilities.join(', '));
        console.log(chalk.cyan('  Tier         :'), passport.tier);
        console.log(chalk.cyan('  Expires      :'), passport.agent.expires_at);
        console.log(chalk.cyan('  Public Key   :'), keys.publicKey.slice(0, 24) + '...');
        if (passport.eu_ai_act) {
          console.log(chalk.cyan('  EU AI Risk   :'), passport.eu_ai_act.risk_level);
        }
        console.log('');
        console.log(chalk.green('  Saved:'), `${opts.output}/passport.json`);
        console.log(chalk.yellow('  Keys (keep secure):'), `${opts.output}/keys.json`);
        console.log('');
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  cmd.command('verify')
    .description('Verify a passport signature and expiry')
    .option('--file <path>', 'Passport JSON file', './.aib/passport.json')
    .action((opts) => {
      try {
        const passport = JSON.parse(readFileSync(opts.file, 'utf8'));
        const result = verifyPassport(passport);

        if (result.valid) {
          console.log(chalk.green('\n✅ Passport is VALID\n'));
        } else {
          console.log(chalk.red('\n❌ Passport is INVALID\n'));
        }
        console.log(chalk.cyan('  Signature OK :'), result.signature_ok ? chalk.green('yes') : chalk.red('no'));
        console.log(chalk.cyan('  Expired      :'), result.expired ? chalk.red('yes') : chalk.green('no'));
        console.log(chalk.cyan('  Expires at   :'), result.expires_at);
        console.log('');
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  cmd.command('export')
    .description('Export passport as W3C Verifiable Credential')
    .option('--file <path>', 'Passport JSON file', './.aib/passport.json')
    .option('--output <path>', 'Output file', './.aib/credential.json')
    .action((opts) => {
      try {
        const passport = JSON.parse(readFileSync(opts.file, 'utf8'));
        const vc = passportToVC(passport);
        writeFileSync(opts.output, JSON.stringify(vc, null, 2));
        console.log(chalk.green('\n✅ Exported as W3C Verifiable Credential\n'));
        console.log(chalk.cyan('  File:'), opts.output);
        console.log('');
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  return cmd;
}
