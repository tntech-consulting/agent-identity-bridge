import { Command } from 'commander';
import chalk from 'chalk';
import { readFileSync } from 'fs';
import { translate, PROTOCOLS } from '../lib/translator.js';

export function translateCommand() {
  const cmd = new Command('translate').description('Translate passport credentials between protocols');

  cmd.command('to')
    .description('Translate a passport to a target protocol format')
    .requiredOption('--protocol <p>', `Target protocol: ${PROTOCOLS.join('|')}`)
    .option('--from <p>', 'Source protocol (auto-detected)', 'mcp')
    .option('--file <path>', 'Passport JSON file', './.aib/passport.json')
    .action((opts) => {
      try {
        const passport = JSON.parse(readFileSync(opts.file, 'utf8'));
        const result = translate(passport, opts.from, opts.protocol);
        console.log(chalk.cyan(`\n🔄 Translated to ${opts.protocol.toUpperCase()}\n`));
        console.log(JSON.stringify(result, null, 2));
        console.log('');
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  cmd.command('protocols')
    .description('List supported protocols')
    .action(() => {
      console.log(chalk.cyan('\n🔄 Supported protocols:\n'));
      PROTOCOLS.forEach(p => console.log(`  ${chalk.bold(p)}`));
      console.log('');
    });

  return cmd;
}
