const test = require('ava');
const { detectSecretsInContent, redactSecret } = require('../lib/secrets');

test('redactSecret should properly redact secrets', t => {
    const redacted1 = redactSecret('AKIAIOSFODNN7EXAMPLE');
    t.true(redacted1.startsWith('AKIA'));
    t.true(redacted1.endsWith('LE'));
    t.true(redacted1.includes('**'));

    t.is(redactSecret('short'), '***REDACTED***');

    const redacted2 = redactSecret('sk_live_FakeTestKeyXXXXXXXXX');
    t.true(redacted2.startsWith('sk_l'));
    t.true(redacted2.endsWith('XX'));
    t.true(redacted2.includes('**'));
});

test('should detect AWS Access Key ID', t => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const secrets = detectSecretsInContent(content, 'test.js');

    t.is(secrets.length, 1);
    t.is(secrets[0].type, 'AWS Access Key ID');
    t.is(secrets[0].confidence, 'high');
});

test('should detect Google API Key', t => {
    const content = 'const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";';
    const secrets = detectSecretsInContent(content, 'test.js');

    const googleKey = secrets.find(s => s.type === 'Google API Key');
    t.truthy(googleKey);
    t.is(googleKey.confidence, 'high');
});

test('should detect Stripe API Key', t => {
    const content = 'stripe.apiKey = "sk_live_FakeTestKeyXXXXXXXXXXXXX";';
    const secrets = detectSecretsInContent(content, 'test.js');

    const stripeKey = secrets.find(s => s.type === 'Stripe API Key');
    t.truthy(stripeKey);
    t.is(stripeKey.confidence, 'high');
});

test('should detect GitHub Token', t => {
    const content = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";';
    const secrets = detectSecretsInContent(content, 'test.js');

    const ghToken = secrets.find(s => s.type === 'GitHub Token');
    t.truthy(ghToken);
    t.is(ghToken.confidence, 'high');
});

test('should detect private RSA key', t => {
    const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...';
    const secrets = detectSecretsInContent(content, 'test.key');

    const privateKey = secrets.find(s => s.type === 'Private Key (RSA)');
    t.truthy(privateKey);
    t.is(privateKey.confidence, 'high');
});

test('should detect JWT tokens', t => {
    const content = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";';
    const secrets = detectSecretsInContent(content, 'test.js');

    const jwt = secrets.find(s => s.type === 'JWT Token');
    t.truthy(jwt);
});

test('should detect generic API keys', t => {
    const content = 'api_key = "abcdef123456789012345678901234567890"';
    const secrets = detectSecretsInContent(content, 'config.txt');

    const apiKey = secrets.find(s => s.type === 'Generic API Key');
    t.truthy(apiKey);
    t.is(apiKey.confidence, 'medium');
});

test('should detect database connection strings', t => {
    const content = 'mongodb://user:pass@localhost:27017/mydb';
    const secrets = detectSecretsInContent(content, 'config.js');

    const connString = secrets.find(s => s.type === 'Database Connection String');
    t.truthy(connString);
    t.is(connString.confidence, 'high');
});

test('should not produce false positives on normal code', t => {
    const content = `
    const API_URL = 'https://api.example.com';
    const VERSION = '1.0.0';
    const PORT = 3000;
  `;
    const secrets = detectSecretsInContent(content, 'constants.js');

    // Should have no high-confidence secrets
    const highConfidence = secrets.filter(s => s.confidence === 'high');
    t.is(highConfidence.length, 0);
});

test('should handle multiple secrets in same file', t => {
    const content = `
    AWS_KEY=AKIAIOSFODNN7EXAMPLE
    GOOGLE_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe
    STRIPE_KEY=sk_live_FakeTestKeyXXXXXXXXXXXXX
  `;
    const secrets = detectSecretsInContent(content, '.env');

    t.true(secrets.length >= 3);
    t.true(secrets.some(s => s.type === 'AWS Access Key ID'));
    t.true(secrets.some(s => s.type === 'Google API Key'));
    t.true(secrets.some(s => s.type === 'Stripe API Key'));
});
