const test = require('ava');
const { scanRepository, generateEnvExample } = require('../index');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

test('integration: full scan of sample repository', async t => {
    // Create a temporary test repository
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'envguard-integration-'));

    try {
        // Create sample files
        await fs.writeFile(path.join(tempDir, 'index.js'), `
const express = require('express');
const app = express();

const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
const port = process.env.PORT ?? 3000;

app.listen(port);
`);

        await fs.writeFile(path.join(tempDir, 'config.js'), `
module.exports = {
  secret: process.env.SECRET_TOKEN,
  stripe: process.env.STRIPE_KEY
};
`);

        await fs.writeFile(path.join(tempDir, '.env'), `
# Sample environment file
API_KEY=test_key_12345
DATABASE_URL=postgresql://localhost:5432/testdb
PORT=3000
SECRET_TOKEN=secret123
STRIPE_KEY=sk_live_FakeTestKeyXXXXXXXXXXXXX
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
`);

        // Run scan
        const results = await scanRepository(tempDir, {
            checkHistory: false,
            deepScan: false
        });

        // Verify environment keys were found
        t.true(results.envKeys.length >= 4);
        const keyNames = results.envKeys.map(k => k.name);
        t.true(keyNames.includes('API_KEY'));
        t.true(keyNames.includes('DATABASE_URL'));
        t.true(keyNames.includes('PORT'));
        t.true(keyNames.includes('SECRET_TOKEN'));

        // Verify secrets were detected
        t.true(results.secrets.length >= 2);

        // Should detect Stripe key
        const stripeSecret = results.secrets.find(s => s.type.includes('Stripe'));
        t.truthy(stripeSecret);
        t.is(stripeSecret.confidence, 'high');

        // Should detect AWS key
        const awsSecret = results.secrets.find(s => s.type.includes('AWS'));
        t.truthy(awsSecret);
        t.is(awsSecret.confidence, 'high');

        // Verify files were scanned
        t.true(results.filesScanned >= 2);

    } finally {
        // Cleanup
        await fs.rm(tempDir, { recursive: true, force: true });
    }
});

test('integration: generate .env.example from .env', async t => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'envguard-integration-'));

    try {
        const envPath = path.join(tempDir, '.env');
        const examplePath = path.join(tempDir, '.env.example');

        await fs.writeFile(envPath, `
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
DATABASE_POOL_SIZE=10

# API Configuration
API_KEY=super_secret_key_12345
API_URL=https://api.example.com

# Server
PORT=3000
HOST=localhost
`);

        const result = await generateEnvExample(envPath);

        t.true(result.success);
        t.is(result.keysFound, 6);

        const exampleContent = await fs.readFile(examplePath, 'utf-8');

        // Should preserve comments
        t.true(exampleContent.includes('# Database Configuration'));
        t.true(exampleContent.includes('# API Configuration'));

        // Should have all keys
        t.true(exampleContent.includes('DATABASE_URL='));
        t.true(exampleContent.includes('API_KEY='));
        t.true(exampleContent.includes('PORT='));

        // Should NOT have actual secrets
        t.false(exampleContent.includes('super_secret_key_12345'));
        t.false(exampleContent.includes('user:password@localhost'));

    } finally {
        await fs.rm(tempDir, { recursive: true, force: true });
    }
});

test('integration: scan with git repository', async t => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'envguard-integration-'));

    try {
        // Initialize git repo
        execSync('git init', { cwd: tempDir, stdio: 'pipe' });
        execSync('git config user.email "test@test.com"', { cwd: tempDir, stdio: 'pipe' });
        execSync('git config user.name "Test User"', { cwd: tempDir, stdio: 'pipe' });

        // Create and commit a .env file (bad practice!)
        await fs.writeFile(path.join(tempDir, '.env'), `
API_KEY=secret123
DATABASE_URL=postgresql://localhost/db
`);

        execSync('git add .env', { cwd: tempDir, stdio: 'pipe' });
        execSync('git commit -m "Initial commit"', { cwd: tempDir, stdio: 'pipe' });

        // Scan repository
        const results = await scanRepository(tempDir, { checkHistory: false });

        // Should detect committed .env file
        t.true(results.envFiles.committedFiles > 0);
        const committedEnv = results.envFiles.envFiles.find(f => f.isCommitted);
        t.truthy(committedEnv);
        t.is(committedEnv.severity, 'high');

    } catch (err) {
        // If git is not available, skip this test
        if (err.message.includes('git')) {
            t.pass('Git not available, skipping git test');
            return;
        }
        throw err;
    } finally {
        await fs.rm(tempDir, { recursive: true, force: true });
    }
});

test('integration: scan respects exclude patterns', async t => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'envguard-integration-'));

    try {
        // Create directory structure
        await fs.mkdir(path.join(tempDir, 'src'));
        await fs.mkdir(path.join(tempDir, 'node_modules'));

        await fs.writeFile(path.join(tempDir, 'src', 'app.js'), `
const key = process.env.API_KEY;
`);

        await fs.writeFile(path.join(tempDir, 'node_modules', 'package.js'), `
const key = process.env.NPM_TOKEN;
`);

        const results = await scanRepository(tempDir);

        // Should find API_KEY but not NPM_TOKEN (node_modules excluded)
        const keyNames = results.envKeys.map(k => k.name);
        t.true(keyNames.includes('API_KEY'));
        t.false(keyNames.includes('NPM_TOKEN'));

    } finally {
        await fs.rm(tempDir, { recursive: true, force: true });
    }
});

test('integration: handle repository with no issues', async t => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'envguard-integration-'));

    try {
        await fs.writeFile(path.join(tempDir, 'index.js'), `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
module.exports = app;
`);

        const results = await scanRepository(tempDir);

        t.is(results.envKeys.length, 0);
        t.is(results.secrets.length, 0);

    } finally {
        await fs.rm(tempDir, { recursive: true, force: true });
    }
});
