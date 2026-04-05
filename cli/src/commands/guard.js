import { Command } from 'commander';
import chalk from 'chalk';
import { evaluateAction } from '../lib/policy.js';

export function guardCommand() {
  const cmd = new Command('guard').description('Pre-action guardrails (exit 0=ALLOW, exit 1=DENY)');

  cmd.command('check')
    .description('Check if an action is allowed by active policies')
    .requiredOption('--action <action>', 'Action to check (e.g. exec.run, data.export)')
    .option('--params <json>', 'Action parameters as JSON', '{}')
    .option('--policy <templates>', 'Comma-separated policy templates', 'minimal-guardrails')
    .action((opts) => {
      try {
        const params = JSON.parse(opts.params);
        const templates = opts.policy.split(',').map(t => t.trim());
        const result = evaluateAction(opts.action, params, templates);

        if (result.decision === 'ALLOW') {
          console.log(chalk.green(`\n✅ ALLOW — ${opts.action}\n`));
          if (result.warnings.length > 0) {
            result.warnings.forEach(w => console.log(chalk.yellow(`  ⚠ ${w.rule}: ${w.reason}`)));
          }
          process.exit(0);
        } else {
          console.log(chalk.red(`\n❌ DENY — ${opts.action}\n`));
          result.violations.forEach(v => console.log(chalk.red(`  ✗ ${v.rule}: ${v.reason}`)));
          console.log('');
          process.exit(1);
        }
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  return cmd;
}
