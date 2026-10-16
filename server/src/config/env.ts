/**
 * Environment configuration.
 *
 * Rules enforced here:
 *   - No secret has a default value. A missing secret is a startup failure,
 *     never a silent fall back to something guessable.
 *   - Production settings are validated as production settings: insecure
 *     combinations refuse to boot rather than warn.
 *   - This module never logs a value it reads.
 */

const REQUIRED_SECRET_MIN_LENGTH = 32;

export type NodeEnv = 'development' | 'test' | 'production';

export interface Config {
  readonly nodeEnv: NodeEnv;
  readonly isProduction: boolean;
  readonly port: number;
  readonly logLevel: string;

  readonly databaseUrl: string;
  readonly databaseSsl: boolean;
  readonly redisUrl: string;

  readonly accessTokenSecret: string;
  readonly refreshTokenSecret: string;
  /**
   * Separate keyspace for invitation-token hashes. Distinct from the refresh
   * pepper so a hash from one table can never match a row in the other.
   */
  readonly invitationTokenPepper: string;
  readonly accessTokenTtl: string;
  readonly refreshTokenTtlDays: number;

  readonly publicOrigin: string;
  readonly corsAllowedOrigins: readonly string[];
  readonly maxRequestBodyBytes: number;
  readonly enableHsts: boolean;
  /**
   * Trust X-Forwarded-For. Enable ONLY when actually behind our reverse proxy:
   * trusting it otherwise lets any client spoof its IP and bypass every per-IP
   * rate limit.
   */
  readonly trustProxy: boolean;

  readonly rateLimits: {
    readonly authPer15m: number;
    readonly registerPerHour: number;
    readonly inviteCreatePerDay: number;
    readonly inviteAcceptPerHour: number;
    readonly prekeyFetchPerHour: number;
    readonly messageSendPerMinute: number;
    readonly wsConnectPerMinute: number;
  };

  readonly retention: {
    readonly queuedMessageTtlDays: number;
    readonly securityEventTtlDays: number;
    readonly invitationTtlHours: number;
  };

  readonly allowBootstrapAccount: boolean;
}

class ConfigError extends Error {
  constructor(message: string) {
    super(`Configuration error: ${message}`);
    this.name = 'ConfigError';
  }
}

function readString(key: string): string {
  const value = process.env[key];
  if (value === undefined || value.trim() === '') {
    throw new ConfigError(`${key} is required and must not be empty`);
  }
  return value.trim();
}

function readOptionalString(key: string, fallback: string): string {
  const value = process.env[key];
  return value === undefined || value.trim() === '' ? fallback : value.trim();
}

function readInt(key: string, fallback: number): number {
  const raw = process.env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new ConfigError(`${key} must be a non-negative integer`);
  }
  return parsed;
}

function readBool(key: string, fallback: boolean): boolean {
  const raw = process.env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const normalised = raw.trim().toLowerCase();
  if (normalised === 'true' || normalised === '1') return true;
  if (normalised === 'false' || normalised === '0') return false;
  throw new ConfigError(`${key} must be true or false`);
}

/**
 * Secrets are length-checked, not merely present-checked. A two-character
 * signing secret is worse than a missing one because it boots.
 */
function readSecret(key: string): string {
  const value = readString(key);
  if (value.length < REQUIRED_SECRET_MIN_LENGTH) {
    throw new ConfigError(
      `${key} must be at least ${REQUIRED_SECRET_MIN_LENGTH} characters`,
    );
  }
  if (value.startsWith('CHANGE_ME')) {
    throw new ConfigError(`${key} still holds the placeholder value from .env.example`);
  }
  return value;
}

function readNodeEnv(): NodeEnv {
  const value = readOptionalString('NODE_ENV', 'development');
  if (value !== 'development' && value !== 'test' && value !== 'production') {
    throw new ConfigError(`NODE_ENV must be development, test or production (got '${value}')`);
  }
  return value;
}

export function loadConfig(): Config {
  const nodeEnv = readNodeEnv();
  const isProduction = nodeEnv === 'production';

  const accessTokenSecret = readSecret('ACCESS_TOKEN_SECRET');
  const refreshTokenSecret = readSecret('REFRESH_TOKEN_SECRET');
  const invitationTokenPepper = readSecret('INVITATION_TOKEN_PEPPER');

  // Distinct secrets are a correctness requirement, not a nicety. Reusing one
  // secret across purposes lets a credential minted for one be presented for
  // another, and lets a hash from one table match a row in the next.
  const secrets = new Map<string, string>([
    ['ACCESS_TOKEN_SECRET', accessTokenSecret],
    ['REFRESH_TOKEN_SECRET', refreshTokenSecret],
    ['INVITATION_TOKEN_PEPPER', invitationTokenPepper],
  ]);
  const seen = new Map<string, string>();
  for (const [name, value] of secrets) {
    const duplicate = seen.get(value);
    if (duplicate !== undefined) {
      throw new ConfigError(`${name} must differ from ${duplicate}`);
    }
    seen.set(value, name);
  }

  const publicOrigin = readOptionalString('PUBLIC_ORIGIN', 'http://localhost:3000');
  const corsAllowedOrigins = readOptionalString('CORS_ALLOWED_ORIGINS', '')
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  const allowBootstrapAccount = readBool('ALLOW_BOOTSTRAP_ACCOUNT', false);
  const databaseSsl = readBool('DATABASE_SSL', false);
  const enableHsts = readBool('ENABLE_HSTS', isProduction);

  const config: Config = {
    nodeEnv,
    isProduction,
    port: readInt('PORT', 3000),
    logLevel: readOptionalString('LOG_LEVEL', isProduction ? 'info' : 'debug'),

    databaseUrl: readString('DATABASE_URL'),
    databaseSsl,
    redisUrl: readString('REDIS_URL'),

    accessTokenSecret,
    refreshTokenSecret,
    invitationTokenPepper,
    accessTokenTtl: readOptionalString('ACCESS_TOKEN_TTL', '15m'),
    refreshTokenTtlDays: readInt('REFRESH_TOKEN_TTL_DAYS', 30),

    publicOrigin,
    corsAllowedOrigins,
    maxRequestBodyBytes: readInt('MAX_REQUEST_BODY_BYTES', 65_536),
    enableHsts,
    trustProxy: readBool('TRUST_PROXY', false),

    rateLimits: {
      authPer15m: readInt('RATE_LIMIT_AUTH_PER_15M', 10),
      registerPerHour: readInt('RATE_LIMIT_REGISTER_PER_HOUR', 5),
      inviteCreatePerDay: readInt('RATE_LIMIT_INVITE_CREATE_PER_DAY', 20),
      inviteAcceptPerHour: readInt('RATE_LIMIT_INVITE_ACCEPT_PER_HOUR', 10),
      prekeyFetchPerHour: readInt('RATE_LIMIT_PREKEY_FETCH_PER_HOUR', 120),
      messageSendPerMinute: readInt('RATE_LIMIT_MESSAGE_SEND_PER_MINUTE', 120),
      wsConnectPerMinute: readInt('RATE_LIMIT_WS_CONNECT_PER_MINUTE', 10),
    },

    retention: {
      queuedMessageTtlDays: readInt('QUEUED_MESSAGE_TTL_DAYS', 30),
      securityEventTtlDays: readInt('SECURITY_EVENT_TTL_DAYS', 90),
      invitationTtlHours: readInt('INVITATION_TTL_HOURS', 72),
    },

    allowBootstrapAccount,
  };

  assertProductionSafety(config);
  return config;
}

/**
 * Fail closed. Each check below corresponds to a way a production deployment
 * could be quietly insecure.
 */
function assertProductionSafety(config: Config): void {
  if (!config.isProduction) return;

  const problems: string[] = [];

  if (config.allowBootstrapAccount) {
    problems.push(
      'ALLOW_BOOTSTRAP_ACCOUNT must be false in production (it is a privileged account-creation path)',
    );
  }
  if (!config.publicOrigin.startsWith('https://')) {
    problems.push('PUBLIC_ORIGIN must use https in production');
  }
  if (config.corsAllowedOrigins.includes('*')) {
    problems.push('CORS_ALLOWED_ORIGINS must not be a wildcard in production');
  }
  if (!config.enableHsts) {
    problems.push('ENABLE_HSTS should be true in production');
  }
  if (config.logLevel === 'trace') {
    problems.push('LOG_LEVEL must not be trace in production (raises the risk of logging payloads)');
  }
  if (process.env['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
    problems.push('NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification and is never acceptable');
  }

  if (problems.length > 0) {
    throw new ConfigError(`refusing to start in production:\n  - ${problems.join('\n  - ')}`);
  }
}

export { ConfigError };
