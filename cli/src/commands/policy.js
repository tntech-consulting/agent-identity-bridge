import { Command } from 'commander';
import chalk from 'chalk';
import { TEMPLATES, evaluateAction } from '../lib/policy.js';

export function policyCommand() {
  const cmd = new Command('policy').description('Governance policy templates');

  cmd.command('list')
    .description('List available policy templates')
    .action(() => {
      console.log(chalk.cyan('\n📋 Available policy templates:\n'));
      for (const [key, tpl] of Object.entries(TEMPLATES)) {
        console.log(chalk.bold(`  ${key}`));
        console.log(chalk.dim(`    ${tpl.description}`));
        console.log(chalk.dim(`    Rules: ${tpl.rules.length}`));
        console.log('');
      }
    });

  cmd.command('show')
    .description('Show template details')
    .requiredOption('--template <name>', 'Template name')
    .action((opts) => {
      const tpl = TEMPLATES[opts.template];
      if (!tpl) {
        console.error(chalk.red(`Template not found: ${opts.template}`));
        console.log(chalk.dim(`Available: ${Object.keys(TEMPLATES).join(', ')}`));
        process.exit(1);
      }
      console.log(chalk.cyan(`\n📋 ${tpl.name}\n`));
      console.log(chalk.dim(`  ${tpl.description}\n`));
      console.log(chalk.bold('  Rules:'));
      tpl.rules.forEach(r => {
        console.log(chalk.cyan(`    [${r.id}]`), chalk.dim(`type: ${r.type}`));
        if (r.patterns) console.log(chalk.dim(`      patterns: ${r.patterns.slice(0, 3).join(', ')}...`));
        if (r.max) console.log(chalk.dim(`      max: ${r.max}`));
      });
      console.log('');
    });

  cmd.command('evaluate')
    .description('Evaluate an action against policies')
    .requiredOption('--action <action>', 'Action to evaluate')
    .option('--params <json>', 'Parameters as JSON', '{}')
    .option('--policy <templates>', 'Templates to apply', 'minimal-guardrails')
    .action((opts) => {
      try {
        const params = JSON.parse(opts.params);
        const templates = opts.policy.split(',').map(t => t.trim());
        const result = evaluateAction(opts.action, params, templates);

        const icon = result.decision === 'ALLOW' ? chalk.green('✅ ALLOW') : chalk.red('❌ DENY');
        console.log(`\n${icon} — ${opts.action}\n`);
        console.log(chalk.dim(`  Rules checked: ${result.rules_checked}`));
        if (result.violations.length > 0) {
          result.violations.forEach(v => console.log(chalk.red(`  ✗ ${v.reason}`)));
        }
        if (result.warnings.length > 0) {
          result.warnings.forEach(w => console.log(chalk.yellow(`  ⚠ ${w.reason}`)));
        }
        console.log('');
        process.exit(result.decision === 'DENY' ? 1 : 0);
      } catch (e) {
        console.error(chalk.red('Error:'), e.message);
        process.exit(1);
      }
    });

  return cmd;
}
