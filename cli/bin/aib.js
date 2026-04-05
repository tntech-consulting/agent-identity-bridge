#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { passportCommand } from '../src/commands/passport.js';
import { guardCommand } from '../src/commands/guard.js';
import { policyCommand } from '../src/commands/policy.js';
import { translateCommand } from '../src/commands/translate.js';

const program = new Command();

console.log(chalk.cyan('\n  AIB Protocol CLI') + chalk.dim(' — Agent Identity Bridge'));
console.log(chalk.dim('  The JWT/OIDC of the agentic era — aib-tech.fr\n'));

program
  .name('aib')
  .description('Agent Identity Bridge — cryptographic identity for AI agents')
  .version('0.1.0');

program.addCommand(passportCommand());
program.addCommand(guardCommand());
program.addCommand(policyCommand());
program.addCommand(translateCommand());

program.parse();
