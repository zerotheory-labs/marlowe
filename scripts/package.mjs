import { packager } from '@electron/packager';

const arg = name => {
  const hit = process.argv.slice(2).find(a => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
};

const platform = arg('platform');
const arch = arg('arch');
const signIdentity = (process.env.APPLE_SIGN_IDENTITY || '').trim();
const appleId = (process.env.APPLE_ID || '').trim();
const appleAppPassword = (process.env.APPLE_APP_SPECIFIC_PASSWORD || '').trim();
const appleTeamId = (process.env.APPLE_TEAM_ID || '').trim();
const isDarwin = (platform || process.platform) === 'darwin';

let osxSign;
let osxNotarize;
if (isDarwin && signIdentity) {
  osxSign = { identity: signIdentity, hardenedRuntime: true };
  if (appleId && appleAppPassword && appleTeamId) {
    osxNotarize = { appleId, appleIdPassword: appleAppPassword, teamId: appleTeamId };
  }
  console.log(`[package] macOS code signing enabled (${osxNotarize ? 'signed + notarized' : 'signed only'}).`);
} else if (isDarwin) {
  console.log('[package] macOS code signing skipped (APPLE_SIGN_IDENTITY not set — producing unsigned bundle).');
}

const paths = await packager({
  dir: '.',
  name: 'Marlowe',
  out: 'release',
  overwrite: true,
  ...(platform ? { platform } : {}),
  ...(arch ? { arch } : {}),
  ...(osxSign ? { osxSign } : {}),
  ...(osxNotarize ? { osxNotarize } : {}),
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
    /^\/\.github/,
    /^\/\.git($|\/)/
  ]
});
console.log(paths.join('\n'));
