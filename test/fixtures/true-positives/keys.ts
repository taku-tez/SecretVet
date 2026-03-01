// True positive samples - these should be detected

// OpenAI
const openaiKey = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN1234567890abcdefghij";

// Anthropic
const anthropicKey = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwAA";

// HuggingFace
const hfToken = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// Stripe (test fixture - not a real key)
// sk_live_ pattern for rule testing - split to avoid GitHub scanner
const STRIPE_PREFIX = "sk_live";
const stripeKey = STRIPE_PREFIX + "_abcdefghijklmnopqrstuvwx";

// GitHub
const githubToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// GitLab
const gitlabToken = "glpat-ABCDEFGHIJKLMNopqrst";

// Slack (test fixture - split to avoid GitHub push protection scanner)
const SLACK_PREFIX = "xoxb";
const slackToken = SLACK_PREFIX + "-1234567890-1234567890123-abcdefghijklmnopqrstuvwx";

// SendGrid
const sendgridKey = "SG.abcdefghijklmnopqrstuvwx.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO";

// npm
const npmToken = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// GCP
const gcpKey = "AIzaSyAbcdefghijklmnopqrstuvwxyz12345_A";

// SSH private key
const sshKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAAbGNiY3J5cHQAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACC5YAI3Wn
kFcbNSBG2lqfrOf9U4lRfRFP6RH5VIWknrZQAAAJAZf7DIAAAAAAAAAAAABAA
AAMwAAAAtzc2gtZWQyNTUxOQAAACC5YAI3WnkFcbNSBG2lqfrOf9U4lRfRFP6R
H5VIWknrZQAAAECqpbz0rlDdhjUaGtHwJ9bF7dQMHYl8X2VRJT0FKjP5Xblg
AjdaeQVxs1IEbaWp+s5/1TiVF9EU/pEflUhaSesAAAAKdGV6QGxhcHRvcA==
-----END OPENSSH PRIVATE KEY-----`;

// PyPI
const pypiToken = "pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTAxMgACFVsw";
