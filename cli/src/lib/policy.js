export const TEMPLATES = {
  'eu-ai-act': {
    name: 'EU AI Act Compliance',
    description: 'Full EU AI Act compliance pack — risk declaration, human oversight, audit trail',
    rules: [
      { id: 'eu-risk-declaration', type: 'require_field', field: 'eu_ai_act.risk_level' },
      { id: 'eu-human-oversight', type: 'require_field', field: 'eu_ai_act.human_oversight' },
      { id: 'eu-transparency', type: 'capability_required', capability: 'audit:write' },
      { id: 'eu-gdpr', type: 'block_pattern', patterns: ['data.export.personal', 'data.delete.bulk'] },
    ],
  },
  'minimal-guardrails': {
    name: 'Minimal Guardrails',
    description: 'Block dangerous system commands and enforce rate limits',
    rules: [
      { id: 'block-destructive', type: 'block_pattern', patterns: [
        'rm -rf', 'format', 'DROP TABLE', 'DELETE FROM', 'shutdown', 'reboot',
        'sudo rm', 'mkfs', '> /dev/', 'dd if=', 'chmod 777', ':(){:|:&};:',
      ]},
      { id: 'rate-limit', type: 'rate_limit', max_per_minute: 60 },
    ],
  },
  'separation-of-duties': {
    name: 'Separation of Duties',
    description: 'Creator != approver for sensitive operations',
    rules: [
      { id: 'sod-financial', type: 'separation_of_duties', operations: ['payment.approve', 'payment.execute'] },
      { id: 'sod-deploy', type: 'separation_of_duties', operations: ['code.review', 'code.deploy'] },
    ],
  },
  'budget-control': {
    name: 'Budget Control',
    description: 'Spending caps and escalation thresholds',
    rules: [
      { id: 'budget-per-op', type: 'cost_limit', field: 'cost_eur', max: 100, action: 'deny' },
      { id: 'budget-daily', type: 'daily_limit', field: 'cost_eur', max: 1000, action: 'escalate' },
    ],
  },
  'delegation-chain': {
    name: 'Delegation Chain',
    description: 'Max delegation depth and capability narrowing',
    rules: [
      { id: 'max-depth', type: 'max_delegation_depth', max: 3 },
      { id: 'capability-narrowing', type: 'require_capability_subset' },
    ],
  },
};

export function evaluateAction(action, params = {}, templates = ['minimal-guardrails']) {
  const results = [];

  for (const tplName of templates) {
    const tpl = TEMPLATES[tplName];
    if (!tpl) continue;

    for (const rule of tpl.rules) {
      if (rule.type === 'block_pattern') {
        const target = JSON.stringify({ action, ...params }).toLowerCase();
        for (const pattern of rule.patterns) {
          if (target.includes(pattern.toLowerCase())) {
            results.push({ rule: rule.id, decision: 'DENY', reason: `Blocked pattern: "${pattern}"` });
          }
        }
      }

      if (rule.type === 'cost_limit' && params[rule.field] !== undefined) {
        if (Number(params[rule.field]) > rule.max) {
          results.push({ rule: rule.id, decision: 'DENY', reason: `${rule.field} ${params[rule.field]} exceeds limit ${rule.max}` });
        }
      }

      if (rule.type === 'require_field' && !params[rule.field]) {
        results.push({ rule: rule.id, decision: 'WARN', reason: `Required field missing: ${rule.field}` });
      }
    }
  }

  const denied = results.filter(r => r.decision === 'DENY');
  return {
    action,
    decision: denied.length > 0 ? 'DENY' : 'ALLOW',
    rules_checked: results.length,
    violations: denied,
    warnings: results.filter(r => r.decision === 'WARN'),
  };
}
