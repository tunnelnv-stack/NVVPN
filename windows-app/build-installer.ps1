param([switch]$SkipBuild,[string]$ReleaseDirectory,[string]$Version,[string]$Commit="uncommitted")
$ErrorActionPreference='Stop'
if(!$Version){$Version=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-version.txt') -Raw).Trim()}
$root=Split-Path $PSScriptRoot -Parent
$release=if($ReleaseDirectory){[IO.Path]::GetFullPath($ReleaseDirectory)}else{Join-Path $root ('release\nvvpn-'+$Version)}
if(Test-Path -LiteralPath (Join-Path $release ('NVVPN-Setup-'+$Version+'-x64.exe'))){throw 'Release exists. Choose a new version or output directory.'}
$payload=Join-Path $release 'app'
if(!$SkipBuild){
    & (Join-Path $PSScriptRoot 'build.ps1') -OutputDirectory $payload -Version $Version
    if($LASTEXITCODE -ne 0){throw 'Application build failed'}
    $report=Join-Path $release 'model-tests.txt'
    $test=Start-Process -FilePath (Join-Path $payload 'NVVPN.exe') -ArgumentList @('--self-test',('"'+$report+'"')) -WindowStyle Hidden -Wait -PassThru
    if($test.ExitCode -ne 0){throw 'Application self-tests failed'}
}
if([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $payload 'NVVPN.exe')).ProductVersion -ne $Version){throw 'Binary version mismatch'}
python (Join-Path $PSScriptRoot 'package.py') --release-dir $release --version $Version --commit $Commit
if($LASTEXITCODE -ne 0){throw 'Source and portable packaging failed'}
$defines=[ordered]@{
    AppHash='NVVPN.exe';ConfigHash='NVVPN.exe.config';EngineHash='NVVPN.Engine.exe';WintunHash='wintun.dll'
    EngineSidecarHash='NVVPN.Engine.exe.sha256';WintunSidecarHash='wintun.dll.sha256';ReadmeHash='README.txt'
    NoticesHash='THIRD-PARTY-NOTICES.txt';DependenciesHash='DEPENDENCIES.json';SourcesHash='NVVPN-Sources.zip';SumsHash='SHA256SUMS.txt'
}
$defines.GetEnumerator() | ForEach-Object {'#define '+$_.Key+' "'+(Get-FileHash -LiteralPath (Join-Path $payload $_.Value)).Hash.ToLowerInvariant()+'"'} | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'installer\hashes.iss') -Encoding ascii
$inno=if($env:NVVPN_ISCC){$env:NVVPN_ISCC}else{Join-Path $root 'tools\inno\ISCC.exe'}
& $inno /Qp ('/DPayloadDir='+$payload) ('/DOutputDir='+$release) ('/DAppVersion='+$Version) (Join-Path $PSScriptRoot 'installer\NVVPN.iss')
if($LASTEXITCODE -ne 0){throw 'Installer compilation failed'}
$setup=Join-Path $release ('NVVPN-Setup-'+$Version+'-x64.exe')
$zip=Join-Path $release ('NVVPN-'+$Version+'-Windows-x64.zip')
$source=Join-Path $release ('NVVPN-'+$Version+'-Source.zip')
Copy-Item -LiteralPath (Join-Path $payload 'NVVPN-Sources.zip') -Destination $source
@($setup,$zip,$source) | ForEach-Object {(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($_)} | Set-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') -Encoding ascii
Get-Item -LiteralPath $setup,$zip | Select-Object Name,Length
