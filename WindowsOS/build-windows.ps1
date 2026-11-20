$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RootDir

$Arch = if ($args.Count -gt 0) { $args[0] } elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }

Write-Host "==> Building Marlowe for Windows (win32-$Arch)..."
npm run build
node scripts/package.mjs --platform=win32 --arch=$Arch
Write-Host "==> Done: release\Marlowe-win32-$Arch\Marlowe.exe"
