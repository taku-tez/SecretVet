import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const HOOK_CONTENT = `#!/bin/sh
# SecretVet pre-commit hook
# Installed by: secretvet install-hook
# To skip: git commit --no-verify

set -e

# Find secretvet binary
if command -v secretvet > /dev/null 2>&1; then
  SECRETVET_BIN="secretvet"
elif [ -f "./node_modules/.bin/secretvet" ]; then
  SECRETVET_BIN="./node_modules/.bin/secretvet"
elif [ -f "./bin/secretvet.js" ]; then
  SECRETVET_BIN="node ./bin/secretvet.js"
else
  echo "⚠️  SecretVet not found. Install with: npm install -g @secretvet/cli"
  exit 0
fi

echo "🔐 SecretVet: Scanning staged files for secrets..."

$SECRETVET_BIN scan --staged --min-severity high --format text

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ SecretVet found secrets in staged files."
  echo "   Fix the issues above, or skip with: git commit --no-verify"
  exit 1
fi

echo "✅ SecretVet: No secrets detected in staged files."
`;

function findGitDir(startPath: string): string | null {
  let current = path.resolve(startPath);
  while (true) {
    const gitDir = path.join(current, '.git');
    if (fs.existsSync(gitDir)) return gitDir;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

export function installHook(cwd: string = process.cwd()): { success: boolean; hookPath: string; message: string } {
  const gitDir = findGitDir(cwd);
  if (!gitDir) {
    return { success: false, hookPath: '', message: 'Not inside a git repository.' };
  }

  const hooksDir = path.join(gitDir, 'hooks');
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = path.join(hooksDir, 'pre-commit');

  // Check if hook already exists
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (existing.includes('SecretVet')) {
      return { success: true, hookPath, message: 'SecretVet hook already installed.' };
    }
    // Append to existing hook
    const newContent = existing.trimEnd() + '\n\n' + HOOK_CONTENT;
    fs.writeFileSync(hookPath, newContent, { mode: 0o755 });
    return { success: true, hookPath, message: 'Appended SecretVet to existing pre-commit hook.' };
  }

  fs.writeFileSync(hookPath, HOOK_CONTENT, { mode: 0o755 });
  return { success: true, hookPath, message: `SecretVet pre-commit hook installed at: ${hookPath}` };
}

export function uninstallHook(cwd: string = process.cwd()): { success: boolean; message: string } {
  const gitDir = findGitDir(cwd);
  if (!gitDir) {
    return { success: false, message: 'Not inside a git repository.' };
  }

  const hookPath = path.join(gitDir, 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) {
    return { success: false, message: 'No pre-commit hook found.' };
  }

  const content = fs.readFileSync(hookPath, 'utf-8');
  if (!content.includes('SecretVet')) {
    return { success: false, message: 'SecretVet hook not found in pre-commit.' };
  }

  // Remove only SecretVet section
  const withoutSecretVet = content.replace(/\n*# SecretVet pre-commit hook[\s\S]*$/, '').trim();
  if (!withoutSecretVet || withoutSecretVet === '#!/bin/sh') {
    fs.unlinkSync(hookPath);
    return { success: true, message: 'SecretVet pre-commit hook removed.' };
  }

  fs.writeFileSync(hookPath, withoutSecretVet + '\n', { mode: 0o755 });
  return { success: true, message: 'SecretVet section removed from pre-commit hook.' };
}
