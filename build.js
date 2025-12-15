import { execSync } from 'child_process';
import { writeFileSync } from 'fs';

console.log('Starting Vercel build...');

// Create a simple package.json for Vercel
const pkg = {
  name: 'cleanconnect-backend',
  version: '1.0.0',
  engines: {
    node: '>=18'
  },
  scripts: {
    build: 'tsc index.ts --outDir dist --module esnext --target es2020'
  }
};

writeFileSync('package-vercel.json', JSON.stringify(pkg, null, 2));
console.log('Build package.json created');