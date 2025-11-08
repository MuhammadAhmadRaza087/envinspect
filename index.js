#!/usr/bin/env node
const { program } = require('commander');
program.version('0.0.1');
program
  .name('envgaurd')
  .description('EnvGaurd — scan repo for env issues & secrets')
  .option('-p, --path <path>', 'path to repository', '.')
  .option('--fix', 'generate .env.example and suggestions')
  .action(async (opts) => {
    console.log('EnvGaurd scanning', opts.path);
    // TODO: implement scan
  });
program.parse(process.argv);
