'use strict';

/**
 * Secret detection patterns for scan-secrets.
 * Each pattern has: id, name, regex, severity, description, redact (chars to show)
 */
const PATTERNS = [
  {
    id: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description: 'AWS Access Key ID — can be used to access AWS services',
    redact: 8
  },
  {
    id: 'AWS_SECRET_KEY',
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi,
    severity: 'critical',
    description: 'AWS Secret Access Key — full AWS account compromise',
    redact: 8
  },
  {
    id: 'GITHUB_PAT',
    name: 'GitHub Personal Access Token (classic)',
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token — grants repo/org access',
    redact: 8
  },
  {
    id: 'GITHUB_OAUTH',
    name: 'GitHub OAuth Token',
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub OAuth access token',
    redact: 8
  },
  {
    id: 'GITHUB_APP_TOKEN',
    name: 'GitHub App Installation Token',
    regex: /\bghs_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'GitHub App installation access token',
    redact: 8
  },
  {
    id: 'GITHUB_PAT_V2',
    name: 'GitHub Fine-Grained PAT',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    severity: 'critical',
    description: 'GitHub fine-grained personal access token (v2)',
    redact: 12
  },
  {
    id: 'NPM_TOKEN',
    name: 'npm Auth Token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    description: 'npm authentication token — can publish packages',
    redact: 8
  },
  {
    id: 'STRIPE_SECRET',
    name: 'Stripe Secret Key',
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe live secret key — full payment processing access',
    redact: 8
  },
  {
    id: 'STRIPE_RESTRICTED',
    name: 'Stripe Restricted Key',
    regex: /\brk_live_[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
    description: 'Stripe restricted key (live mode)',
    redact: 8
  },
  {
    id: 'STRIPE_TEST',
    name: 'Stripe Test Key',
    regex: /\bsk_test_[A-Za-z0-9]{24,}\b/g,
    severity: 'medium',
    description: 'Stripe test secret key — not production but still a secret',
    redact: 8
  },
  {
    id: 'SLACK_TOKEN',
    name: 'Slack API Token',
    regex: /\bxox[baprs]-[0-9A-Za-z]{10,48}\b/g,
    severity: 'high',
    description: 'Slack API token — can read/write messages',
    redact: 8
  },
  {
    id: 'SLACK_WEBHOOK',
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g,
    severity: 'high',
    description: 'Slack incoming webhook URL — can post to channels',
    redact: 20
  },
  {
    id: 'GOOGLE_API_KEY',
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
    description: 'Google API key — can incur charges and access Google services',
    redact: 8
  },
  {
    id: 'SENDGRID_KEY',
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
    severity: 'high',
    description: 'SendGrid API key — can send emails and read contact lists',
    redact: 8
  },
  {
    id: 'TWILIO_SID',
    name: 'Twilio Account SID',
    regex: /\bAC[a-f0-9]{32}\b/g,
    severity: 'medium',
    description: 'Twilio Account SID (often paired with auth token)',
    redact: 8
  },
  {
    id: 'TWILIO_TOKEN',
    name: 'Twilio Auth Token',
    regex: /(?:twilio.*(?:auth|token)|(?:auth|token).*twilio)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi,
    severity: 'high',
    description: 'Twilio Auth Token — SMS/voice API access',
    redact: 8
  },
  {
    id: 'MAILGUN_KEY',
    name: 'Mailgun API Key',
    regex: /\bkey-[a-z0-9]{32}\b/g,
    severity: 'high',
    description: 'Mailgun API key — can send emails',
    redact: 8
  },
  {
    id: 'PRIVATE_KEY_PEM',
    name: 'PEM Private Key',
    regex: /-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s|ENCRYPTED\s)?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Private key in PEM format — cryptographic key compromise',
    redact: 0
  },
  {
    id: 'GENERIC_PASSWORD',
    name: 'Generic Password Assignment',
    regex: /(?:^|[\s,;{(\[])(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*['"]([^'"$\s]{8,})['"](?:\s|,|;|}|\]|\)|$)/gim,
    severity: 'medium',
    description: 'Hardcoded password or secret value detected',
    redact: 4
  },
  {
    id: 'GENERIC_SECRET_ENV',
    name: 'Secret in .env assignment',
    regex: /^(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|CLIENT_SECRET)\s*=\s*['"]?([^'"#\s]{8,})['"]?/gim,
    severity: 'high',
    description: 'Secret-looking value in environment variable assignment',
    redact: 4
  },
  {
    id: 'BEARER_TOKEN',
    name: 'Bearer Token in Code',
    regex: /(?:Authorization|authorization)\s*[:=]\s*['"]?Bearer\s+([A-Za-z0-9\-._~+/]{20,})['"]?/g,
    severity: 'high',
    description: 'Hardcoded Bearer token (OAuth / JWT)',
    redact: 8
  },
  {
    id: 'BASIC_AUTH_URL',
    name: 'Basic Auth Credentials in URL',
    regex: /https?:\/\/[^:@\s"']+:[^@\s"']+@[^/\s"']+/g,
    severity: 'high',
    description: 'Username:password embedded in a URL',
    redact: 8
  },
  {
    id: 'JWT_TOKEN',
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/g,
    severity: 'medium',
    description: 'JSON Web Token (JWT) — may contain session or identity data',
    redact: 16
  },
  {
    id: 'OPENAI_KEY',
    name: 'OpenAI API Key',
    regex: /\bsk-[A-Za-z0-9]{48}\b/g,
    severity: 'critical',
    description: 'OpenAI API key — can incur large charges',
    redact: 8
  },
  {
    id: 'ANTHROPIC_KEY',
    name: 'Anthropic API Key',
    regex: /\bsk-ant-[A-Za-z0-9\-_]{95,}\b/g,
    severity: 'critical',
    description: 'Anthropic API key — Claude API access',
    redact: 8
  }
];

/**
 * File extensions to skip during scanning (binary / irrelevant)
 */
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.obj',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.ttf', '.woff', '.woff2', '.eot', '.otf',
  '.lock', // package-lock.json handled separately
  '.map'   // source maps
]);

/**
 * Directory names to always skip
 */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'coverage',
  '.nyc_output', '.cache', '__pycache__', '.tox', 'venv', '.venv',
  '.next', '.nuxt', 'out', '.parcel-cache', '.turbo'
]);

module.exports = { PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS };
