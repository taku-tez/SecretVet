import { scan } from './scanner.js';
import { formatOutput } from './reporter.js';
import { ALL_RULES, CATEGORIES } from './rules/index.js';
import type { ScanOptions, Severity } from './types.js';

const VERSION = '0.1.0';

function help(): void {
  console.log(`
SecretVet v${VERSION} — Secret & Credential Scanner

Usage:
  secretvet scan <path> [options]
  secretvet rules list [--category <cat>]
  secretvet --version
  secretvet --help

Scan Options:
  --format <text|json|sarif>   Output format (default: text)
  --min-severity <level>       Minimum severity: critical|high|medium|low|info
  --ignore <patterns>          Comma-separated ignore patterns
  --show-secrets               Show unmasked secret values (use carefully!)
  --no-entropy                 Disable entropy-based detection
  --entropy-threshold <num>    Entropy threshold (default: 3.5)
  --verbose                    Verbose output

Categories: ${CATEGORIES.join(', ')}

Examples:
  secretvet scan .
  secretvet scan ./src --format json
  secretvet scan . --min-severity high --format sarif
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
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        flags[key] = argv[i + 1];
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
  if (!target) {
    console.error('Error: scan target path is required');
    process.exit(1);
  }

  const options: ScanOptions = {
    format: (flags['format'] as 'text' | 'json' | 'sarif') ?? 'text',
    minSeverity: flags['min-severity'] as Severity | undefined,
    ignore: flags['ignore'] ? String(flags['ignore']).split(',') : undefined,
    showSecrets: flags['show-secrets'] === true,
    entropy: flags['no-entropy'] !== true,
    entropyThreshold: flags['entropy-threshold'] ? Number(flags['entropy-threshold']) : undefined,
    verbose: flags['verbose'] === true,
  };

  try {
    const result = await scan(target, options);
    const output = formatOutput(result, options.format);
    process.stdout.write(output);

    // Exit with non-zero if findings exist
    if (result.summary.critical > 0 || result.summary.high > 0) {
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

function runRulesList(flags: Record<string, string | boolean>): void {
  const category = flags['category'] as string | undefined;
  const rules = category ? ALL_RULES.filter(r => r.category === category) : ALL_RULES;

  if (rules.length === 0) {
    console.log(`No rules found for category: ${category}`);
    return;
  }

  const maxIdLen = Math.max(...rules.map(r => r.id.length));
  const maxSevLen = 8;

  console.log(`\nSecretVet Rules (${rules.length} total)\n`);
  console.log(`${'ID'.padEnd(maxIdLen + 2)} ${'SEVERITY'.padEnd(maxSevLen + 2)} CATEGORY    DESCRIPTION`);
  console.log('─'.repeat(100));

  for (const rule of rules) {
    const sev = rule.severity.toUpperCase().padEnd(maxSevLen);
    const cat = rule.category.padEnd(12);
    const desc = rule.description.length > 60 ? rule.description.slice(0, 57) + '...' : rule.description;
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
    case 'rules': {
      const subCommand = args[0];
      if (subCommand === 'list') {
        runRulesList(flags);
      } else {
        console.error(`Unknown rules subcommand: ${subCommand}`);
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
