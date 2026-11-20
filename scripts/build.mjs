import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist', { recursive: true });
await build({ entryPoints: ['src/app.js'], bundle: true, outfile: 'dist/app.js', platform: 'browser', loader: { '.woff2': 'file' }, assetNames: 'fonts/[name]-[hash]', target: 'chrome140', minify: !process.argv.includes('--dev'), sourcemap: true });
await copyFile('src/index.html', 'dist/index.html');
console.log('Marlowe renderer built.');
