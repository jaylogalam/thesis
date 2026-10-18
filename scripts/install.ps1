# Installs `runtime-monitor` into %USERPROFILE%\.cargo\bin (Windows).
$ErrorActionPreference = 'Stop'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo not found. Install Rust (https://rustup.rs) with the MSVC toolchain and 'Visual Studio Build Tools' (C++ workload)."
}
cargo install --path (Join-Path $PSScriptRoot '..\app') --locked --force
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Installed. Run: runtime-monitor --help   (live capture needs an elevated/Administrator shell)"
