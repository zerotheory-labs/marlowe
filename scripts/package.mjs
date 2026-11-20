import { packager } from '@electron/packager';

const arg = name => {
  const hit = process.argv.slice(2).find(a => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
};

const platform = arg('platform');
const arch = arg('arch');

const paths = await packager({
  dir: '.',
  name: 'Marlowe',
  out: 'release',
  overwrite: true,
  ...(platform ? { platform } : {}),
  ...(arch ? { arch } : {}),
  asar: { unpack: '**/node-pty/**' },
  appBundleId: 'com.zerotheorylabs.marlowe',
  appCategoryType: 'public.app-category.developer-tools',
  ignore: [
    /^\/release/,
    /^\/test/,
    /^\/scripts/,
    /^\/src/,
    /^\/docs/,
    /^\/MacOS/,
    /^\/WindowsOS/,
    /^\/LinuxOS/,
    /^\/\.test-data/,
    /^\/\.live-agent/,
    /^\/examples/,
    /^\/test-results/,
    /^\/playwright-report/,
    /^\/\.git($|\/)/
  ]
});
console.log(paths.join('\n'));
