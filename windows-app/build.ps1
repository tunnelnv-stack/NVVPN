param([switch]$SkipEngine,[string]$OutputDirectory,[string]$Version)
$ErrorActionPreference='Stop'
if(!$Version){$Version=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-version.txt') -Raw).Trim()}
if($Version -notmatch '^0\.[0-9]+\.[0-9]+$'){throw 'Version must be numeric 0.MINOR.PATCH'}
if($Version -ne (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-version.txt') -Raw).Trim()){throw 'Version does not match source tree'}
$root=Split-Path $PSScriptRoot -Parent
$out=if($OutputDirectory){[IO.Path]::GetFullPath($OutputDirectory)}else{Join-Path $root ('release\nvvpn-'+$Version+'\app')}
New-Item -ItemType Directory -Force -Path $out | Out-Null
& (Join-Path $PSScriptRoot 'installer\make-icon.ps1')
if(!$SkipEngine){
    $env:GOPATH=Join-Path $root 'tools\split-prototype\gopath'
    $env:GOCACHE=Join-Path $root 'tools\split-prototype\gocache'
    $env:GOTOOLCHAIN='local'
    $go=if($env:NVVPN_GO){$env:NVVPN_GO}else{Join-Path $root 'tools\split-prototype\toolchain\go\bin\go.exe'}
    Push-Location (Join-Path $PSScriptRoot 'engine')
    try {
        & $go test -tags with_gvisor ./...
        if($LASTEXITCODE -ne 0){throw 'Go tests failed'}
        & $go build -trimpath -tags with_gvisor -ldflags='-s -w' -o (Join-Path $out 'NVVPN.Engine.exe') .
        if($LASTEXITCODE -ne 0){throw 'Go build failed'}
    }finally{Pop-Location}
}
$framework=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
Copy-Item -LiteralPath (Join-Path $root 'vendor\engine\wintun.dll') -Destination (Join-Path $out 'wintun.dll') -Force
$coreHash=(Get-FileHash -LiteralPath (Join-Path $out 'NVVPN.Engine.exe')).Hash.ToLowerInvariant()
$wintunHash=(Get-FileHash -LiteralPath (Join-Path $out 'wintun.dll')).Hash.ToLowerInvariant()
$hashSource=Join-Path $out 'EngineHashes.generated.cs'
('namespace FinlandVPN { internal static class EngineHashes { internal const string Core = "'+$coreHash+'"; internal const string Wintun = "'+$wintunHash+'"; } }') | Set-Content -LiteralPath $hashSource -Encoding ascii
$refs=@('System.IO.Compression.dll','System.IO.Compression.FileSystem.dll','System.dll','System.Core.dll','System.Security.dll','System.ServiceProcess.dll','System.Web.Extensions.dll','System.Xaml.dll','System.Drawing.dll','System.Windows.Forms.dll','WPF\WindowsBase.dll','WPF\PresentationCore.dll','WPF\PresentationFramework.dll')
$argsList=@('/nologo','/target:winexe','/platform:x64','/warnaserror+','/optimize+',('/out:'+(Join-Path $out 'NVVPN.exe')),('/win32manifest:'+(Join-Path $PSScriptRoot 'app.manifest')))
$argsList+=$refs|ForEach-Object{'/reference:'+(Join-Path $framework $_)}
$versionSource=Join-Path $out 'Version.generated.cs'
('[assembly: System.Reflection.AssemblyVersion("'+$Version+'.0")][assembly: System.Reflection.AssemblyInformationalVersion("'+$Version+'")]') | Set-Content -LiteralPath $versionSource -Encoding ascii
$argsList+=@($versionSource)
foreach($file in @('Updates.cs','UpdateInstall.cs','UpdateUI.cs','UpdateTests.cs','UpdateScenario.cs','UpdateTrust.cs')){$argsList+=(Join-Path $PSScriptRoot $file)}
$argsList+=@((Join-Path $PSScriptRoot 'LocalDiagnostics.cs'),(Join-Path $PSScriptRoot 'Agreement.cs'),(Join-Path $PSScriptRoot 'AgreementDialog.cs'),(Join-Path $PSScriptRoot 'AgreementTests.cs'),(Join-Path $PSScriptRoot 'App.cs'),(Join-Path $PSScriptRoot 'MainWindow.cs'),(Join-Path $PSScriptRoot 'Lifecycle.cs'),(Join-Path $PSScriptRoot 'Startup.cs'),(Join-Path $root 'src\Profile.cs'),$hashSource)
$argsList+=('/resource:'+(Join-Path $PSScriptRoot 'MainWindow.xaml')+',MainWindow.xaml')
$argsList+=('/resource:'+(Join-Path $PSScriptRoot 'assets\ConnectionArt.jpg')+',ConnectionArt.jpg')
$argsList+=('/resource:'+(Join-Path $PSScriptRoot 'Agreement.ru.txt')+',Agreement.ru.txt')
$argsList+=('/resource:'+(Join-Path $PSScriptRoot 'release-notes.txt')+',ReleaseNotes.txt')
$argsList+=('/win32icon:'+(Join-Path $PSScriptRoot 'installer\NVVPN.ico'))
& (Join-Path $framework 'csc.exe') @argsList
if($LASTEXITCODE -ne 0){throw 'UI build failed'}
@'
<?xml version="1.0" encoding="utf-8"?>
<configuration><startup><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8"/></startup></configuration>
'@ | Set-Content -LiteralPath (Join-Path $out 'NVVPN.exe.config') -Encoding utf8
foreach($name in @('NVVPN.Engine.exe','wintun.dll')){if(Test-Path (Join-Path $out $name)){(Get-FileHash -LiteralPath (Join-Path $out $name)).Hash.ToLowerInvariant()|Set-Content -LiteralPath (Join-Path $out ($name+'.sha256')) -Encoding ascii}}
Write-Output ('Built NVVPN: '+$out)
