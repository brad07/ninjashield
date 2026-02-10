/**
 * NinjaShield Hook for OpenClaw
 *
 * Evaluates shell commands before execution using the NinjaShield daemon.
 */

import { HookContext, HookResult } from '@openclaw/hooks';

const NINJASHIELD_URL = process.env.NINJASHIELD_URL || 'http://localhost:7575';
const NINJASHIELD_TIMEOUT = parseInt(process.env.NINJASHIELD_TIMEOUT || '15', 10) * 1000;

interface NinjaShieldResponse {
  decision: 'ALLOW' | 'DENY' | 'ASK' | 'REDACT';
  risk_score: number;
  risk_categories: string[];
  reason_codes: string[];
  context: string;
  policy_id: string;
}

async function evaluateCommand(command: string, cwd?: string): Promise<NinjaShieldResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), NINJASHIELD_TIMEOUT);

  try {
    const response = await fetch(`${NINJASHIELD_URL}/v1/commands/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command,
        cwd: cwd || process.cwd(),
        tool: 'openclaw',
        user: process.env.USER || 'unknown',
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`NinjaShield returned ${response.status}`);
    }

    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function isNinjaShieldAvailable(): Promise<boolean> {
  try {
    const response = await fetch(`${NINJASHIELD_URL}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

export default async function handler(ctx: HookContext): Promise<HookResult> {
  // Only handle exec:before events
  if (ctx.event !== 'exec:before') {
    return { continue: true };
  }

  const { command, cwd } = ctx.payload as { command: string; cwd?: string };

  if (!command) {
    return { continue: true };
  }

  // Check if NinjaShield is available
  if (!(await isNinjaShieldAvailable())) {
    // Fail closed - deny if daemon not running
    return {
      continue: false,
      error: 'NinjaShield daemon is not running. Start it with: ninjashieldd',
    };
  }

  try {
    const result = await evaluateCommand(command, cwd);

    switch (result.decision) {
      case 'ALLOW':
        return { continue: true };

      case 'DENY':
        return {
          continue: false,
          error: `[NinjaShield Risk: ${result.risk_score}] ${result.context || 'Command blocked by security policy'}`,
        };

      case 'ASK':
        // Return approval request for OpenClaw's approval flow
        return {
          continue: false,
          approval: {
            required: true,
            reason: `[NinjaShield Risk: ${result.risk_score}] ${result.context || 'Command requires approval'}`,
            metadata: {
              risk_score: result.risk_score,
              risk_categories: result.risk_categories,
              reason_codes: result.reason_codes,
            },
          },
        };

      case 'REDACT':
        // Could implement command rewriting here
        return {
          continue: false,
          approval: {
            required: true,
            reason: `[NinjaShield] Command contains sensitive data that should be redacted`,
          },
        };

      default:
        return { continue: true };
    }
  } catch (error) {
    // Fail closed on errors
    return {
      continue: false,
      error: `NinjaShield evaluation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}
