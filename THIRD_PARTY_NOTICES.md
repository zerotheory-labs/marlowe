# Third-Party Notices

Marlowe (`v0.4.0`) bundles or depends on the following open-source components and typefaces. Their original licenses govern those respective components and remain unmodified.

## Bundled Typefaces (`src/fonts/`)

- **Newsreader Variable** (`Newsreader-Variable.woff2`)
  - Copyright (c) Production Type (https://www.productiontype.com)
  - License: SIL Open Font License 1.1 (https://openfontlicense.org)

- **Geist & Geist Mono Variable** (`Geist-Variable.woff2`, `GeistMono-Variable.woff2`)
  - Copyright (c) Vercel, Inc. (https://vercel.com/font)
  - License: SIL Open Font License 1.1 (https://openfontlicense.org)

## Runtime Dependencies (`package.json`)

- **Electron** (`electron`) — Copyright (c) Electron contributors. Licensed under the MIT License.
- **xterm.js & @xterm/addon-fit** (`@xterm/xterm`, `@xterm/addon-fit`) — Copyright (c) The xterm.js authors. Licensed under the MIT License.
- **node-pty** (`node-pty`) — Copyright (c) Microsoft Corporation. Licensed under the MIT License.

## Optional External Security CLIs (User-Installed)

Marlowe's Toolchain Doctor and `run_security_scanner` integrate with external security CLIs installed separately by the user on their host (`semgrep`, `trivy`, `gitleaks`, `osv-scanner`, `nmap`, `nuclei`, `tshark`, `radare2`, and `otool`). None of these binaries are bundled or redistributed with Marlowe; each is governed by its own upstream license when installed on your machine.
