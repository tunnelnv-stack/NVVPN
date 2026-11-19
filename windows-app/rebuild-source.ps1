param([Parameter(Mandatory=$true)][string]$GoExecutable,[Parameter(Mandatory=$true)][string]$InnoCompiler,[string]$ReleaseDirectory)
$ErrorActionPreference='Stop'
# Run from the extracted NVVPN source tree. Does not install or launch the VPN.
$env:NVVPN_GO=(Resolve-Path -LiteralPath $GoExecutable).Path
$env:NVVPN_ISCC=(Resolve-Path -LiteralPath $InnoCompiler).Path
$env:GOPROXY='off'
$env:GOSUMDB='off'
$env:GOTOOLCHAIN='local'
if(!$ReleaseDirectory){$ReleaseDirectory=Join-Path (Split-Path $PSScriptRoot -Parent) ('rebuilt-'+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-version.txt') -Raw).Trim())}
& (Join-Path $PSScriptRoot 'build-installer.ps1') -ReleaseDirectory $ReleaseDirectory
