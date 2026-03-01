import { scan } from './scanner.js';
import { scanGitHistory, scanStagedFiles } from './git-scanner.js';
import { formatOutput, formatGitText } from './reporter.js';
import { verifyFindings, canVerify } from './verifier.js';
import { ALL_RULES, CATEGORIES } from './rules/index.js';
import {
  loadBaseline, saveBaseline, createBaseline, filterBaselineFindings, updateBaseline,
} from './baseline.js';
import { installHook, uninstallHook } from './hook.js';
import type { ScanOptions, Severity } from './types.js';

const VERSION = '0.1.0';
const DEFAULT_BASELINE = '.secretvet-baseline.json';

function help(): void {
  console.log(`
SecretVet v${VERSION} — Secret & Credential Scanner

Usage:
  secretvet scan [path] [options]
  secretvet rules list [--category <cat>]
  secretvet baseline create [--note <text>]
  secretvet baseline update [--note <text>]
  secretvet install-hook
  secretvet uninstall-hook
  secretvet --version
  secretvet --help

Scan Options:
  --format <text|json|sarif>   Output format (default: text)
  --min-severity <level>       Minimum severity: critical|high|medium|low|info
  --ignore <patterns>          Comma-separated ignore patterns
  --show-secrets               Show unmasked secret values
  --verify                     Verify if detected secrets are still active (requires --show-secrets)
  --no-entropy                 Disable entropy-based detection
  --git-history                Scan git commit history
  --since <date>               Scan commits since date (e.g. "2025-01-01")
  --until <date>               Scan commits until date
  --max-commits <n>            Max commits to scan in git history
  --staged                     Scan only staged files (pre-commit use)
  --baseline [path]            Load baseline and only report new findings
  --verbose                    Verbose output

Categories: ${CATEGORIES.join(', ')}

Examples:
  secretvet scan .
  secretvet scan ./src --format sarif
  secretvet scan . --git-history --since "2025-01-01"
  secretvet scan . --staged
  secretvet scan . --baseline
  secretvet baseline create
  secretvet install-hook
  secretvet rules list --category cloud
`);
}

function parseArgs(argv: string[]): { command: string; args: string[]; flags: Record<string, string | boolean> } {
  const flags: Record<string, string | boolean> = {};
  const args: string[] = [];
  let command = '';

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i += 2;
      } else {
        flags[key] = true;
        i++;
      }
    } else if (!command) {
      command = arg;
      i++;
    } else {
      args.push(arg);
      i++;
    }
  }

  return { command, args, flags };
}

async function runScan(target: string, flags: Record<string, string | boolean>): Promise<void> {
  const format = (flags['format'] as 'text' | 'json' | 'sarif') ?? 'text';
  const options: ScanOptions = {
    format,
    minSeverity: flags['min-severity'] as Severity | undefined,
    ignore: flags['ignore'] ? String(flags['ignore']).split(',') : undefined,
    showSecrets: flags['show-secrets'] === true,
    entropy: flags['no-entropy'] !== true,
    verbose: flags['verbose'] === true,
  };

  const useBaseline = flags['baseline'] !== undefined;
  const baselinePath = typeof flags['baseline'] === 'string' ? flags['baseline'] : DEFAULT_BASELINE;

  try {
    // -- Staged files mode
    if (flags['staged'] === true) {
      const cwd = target !== '.' ? target : process.cwd();
      const findings = await scanStagedFiles(cwd, options);

      if (findings.length === 0) {
        console.log('✅ No secrets detected in staged files.');
        return;
      }

      const result = {
        target: cwd,
        timestamp: new Date().toISOString(),
        duration: 0,
        filesScanned: findings.length,
        filesSkipped: 0,
        findings,
        summary: {
          critical: findings.filter(f => f.severity === 'critical').length,
          high: findings.filter(f => f.severity === 'high').length,
          medium: findings.filter(f => f.severity === 'medium').length,
          low: findings.filter(f => f.severity === 'low').length,
          info: findings.filter(f => f.severity === 'info').length,
          total: findings.length,
        },
        version: VERSION,
        errors: [],
      };

      process.stdout.write(formatOutput(result, format));
      if (result.summary.critical > 0 || result.summary.high > 0) process.exit(1);
      return;
    }

    // -- Git history mode
    if (flags['git-history'] === true) {
      const { scanGitHistory } = await import('./git-scanner.js');
      const gitResult = await scanGitHistory(target, {
        ...options,
        since: flags['since'] as string | undefined,
        until: flags['until'] as string | undefined,
        maxCommits: flags['max-commits'] ? Number(flags['max-commits']) : undefined,
      });

      if (format === 'json') {
        console.log(JSON.stringify(gitResult, null, 2));
      } else {
        process.stdout.write(formatGitText(gitResult));
      }

      if (gitResult.summary.critical > 0 || gitResult.summary.high > 0) process.exit(1);
      return;
    }

    // -- Normal scan
    const result = await scan(target, options);

    if (useBaseline) {
      const baseline = loadBaseline(baselinePath);
      const { newFindings, baselineFindings } = filterBaselineFindings(result.findings, baseline);

      if (options.verbose) {
        console.log(`ℹ️  Baseline: ${baselineFindings.length} known findings suppressed`);
      }

      result.findings = newFindings;
      result.summary = {
        critical: newFindings.filter(f => f.severity === 'critical').length,
        high: newFindings.filter(f => f.severity === 'high').length,
        medium: newFindings.filter(f => f.severity === 'medium').length,
        low: newFindings.filter(f => f.severity === 'low').length,
        info: newFindings.filter(f => f.severity === 'info').length,
        total: newFindings.length,
      };
    }

    process.stdout.write(formatOutput(result, format));

    // -- Optional verification
    if (flags['verify'] === true && result.findings.length > 0) {
      const verifiableFindings = result.findings.filter(f => canVerify(f.ruleId));
      if (verifiableFindings.length > 0) {
        console.log(`\n🔍 Verifying ${verifiableFindings.length} finding(s)...\n`);
        const verifyResults = await verifyFindings(verifiableFindings);
        for (const vr of verifyResults) {
          const icon = vr.status === 'active' ? '🔴 ACTIVE' : vr.status === 'inactive' ? '✅ REVOKED' : '❓ UNKNOWN';
          console.log(`  ${icon}  ${vr.ruleId} (${vr.file}:${vr.line})`);
          console.log(`          ${vr.message}`);
        }
        console.log('');
      }
    }

    if (result.summary.critical > 0 || result.summary.high > 0) process.exit(1);

  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

async function runBaselineCreate(flags: Record<string, string | boolean>, target: string): Promise<void> {
  const baselinePath = typeof flags['output'] === 'string' ? flags['output'] : DEFAULT_BASELINE;
  const note = typeof flags['note'] === 'string' ? flags['note'] : undefined;

  console.log(`🔐 SecretVet: Scanning ${target} to create baseline...`);
  const result = await scan(target, { showSecrets: false });
  const baseline = createBaseline(result, note);
  saveBaseline(baseline, baselinePath);

  console.log(`✅ Baseline created: ${baselinePath}`);
  console.log(`   ${baseline.entries.length} finding(s) added to baseline`);
}

async function runBaselineUpdate(flags: Record<string, string | boolean>, target: string): Promise<void> {
  const baselinePath = typeof flags['output'] === 'string' ? flags['output'] : DEFAULT_BASELINE;
  const note = typeof flags['note'] === 'string' ? flags['note'] : undefined;

  console.log(`🔐 SecretVet: Scanning ${target} to update baseline...`);
  const existing = loadBaseline(baselinePath);
  const result = await scan(target, { showSecrets: false });
  const updated = updateBaseline(existing, result.findings, note);
  saveBaseline(updated, baselinePath);

  const newCount = updated.entries.length - existing.entries.length;
  console.log(`✅ Baseline updated: ${baselinePath}`);
  console.log(`   ${newCount} new finding(s) added (total: ${updated.entries.length})`);
}

function runRulesList(flags: Record<string, string | boolean>): void {
  const category = flags['category'] as string | undefined;
  const rules = category ? ALL_RULES.filter(r => r.category === category) : ALL_RULES;

  if (rules.length === 0) {
    console.log(`No rules found for category: ${category}`);
    return;
  }

  const maxIdLen = Math.max(...rules.map(r => r.id.length));

  console.log(`\nSecretVet Rules (${rules.length} total)\n`);
  console.log(`${'ID'.padEnd(maxIdLen + 2)} ${'SEVERITY'.padEnd(10)} CATEGORY    DESCRIPTION`);
  console.log('─'.repeat(100));

  for (const rule of rules) {
    const sev = rule.severity.toUpperCase().padEnd(10);
    const cat = rule.category.padEnd(12);
    const desc = rule.description.length > 55 ? rule.description.slice(0, 52) + '...' : rule.description;
    console.log(`${rule.id.padEnd(maxIdLen + 2)} ${sev} ${cat} ${desc}`);
  }

  console.log('');
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    help();
    return;
  }

  if (argv[0] === '--version' || argv[0] === '-v') {
    console.log(VERSION);
    return;
  }

  const { command, args, flags } = parseArgs(argv);

  switch (command) {
    case 'scan': {
      const target = args[0] ?? '.';
      await runScan(target, flags);
      break;
    }
    case 'baseline': {
      const sub = args[0];
      const target = args[1] ?? '.';
      if (sub === 'create') {
        await runBaselineCreate(flags, target);
      } else if (sub === 'update') {
        await runBaselineUpdate(flags, target);
      } else {
        console.error(`Unknown baseline subcommand: ${sub ?? '(none)'}`);
        console.error('Usage: secretvet baseline create|update [path]');
        process.exit(1);
      }
      break;
    }
    case 'install-hook': {
      const cwd = args[0] ?? process.cwd();
      const result = installHook(cwd);
      console.log(result.success ? `✅ ${result.message}` : `❌ ${result.message}`);
      if (!result.success) process.exit(1);
      break;
    }
    case 'uninstall-hook': {
      const cwd = args[0] ?? process.cwd();
      const result = uninstallHook(cwd);
      console.log(result.success ? `✅ ${result.message}` : `❌ ${result.message}`);
      if (!result.success) process.exit(1);
      break;
    }
    case 'rules': {
      const sub = args[0];
      if (sub === 'list') {
        runRulesList(flags);
      } else {
        console.error(`Unknown rules subcommand: ${sub}`);
        process.exit(1);
      }
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      help();
      process.exit(1);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
