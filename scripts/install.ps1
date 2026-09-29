# Install a mjolnir release binary on Windows (x64 or ARM64).
#
# Downloads from the release's public URLs, so it needs no GitHub login or
# token. The archive is checked against the release's SHA256SUMS before
# anything is installed, and the install directory is added to the user PATH.
#
# usage: scripts/install.ps1 [-Version v0.1.0] [-InstallDir DIR] [-Repo owner/name]
#   Each parameter defaults to MJOLNIR_VERSION, MJOLNIR_INSTALL_DIR and
#   MJOLNIR_REPO, then to latest, %LOCALAPPDATA%\Programs\mjolnir and
#   mrquantumoff/mjolnir.
param(
    [string]$Version = $(if ($env:MJOLNIR_VERSION) { $env:MJOLNIR_VERSION } else { 'latest' }),
    [string]$InstallDir = $(if ($env:MJOLNIR_INSTALL_DIR) { $env:MJOLNIR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\mjolnir' }),
    [string]$Repo = $(if ($env:MJOLNIR_REPO) { $env:MJOLNIR_REPO } else { 'mrquantumoff/mjolnir' })
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The directory goes into the user PATH, so it must be one absolute
# filesystem path: a relative entry would resolve against whatever folder a
# later terminal starts in, and a ';' would split it into several entries.
if ($InstallDir.Contains(';')) {
    throw "install: the install directory must not contain ';', the PATH separator: $InstallDir"
}
$InstallDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
if (-not [System.IO.Path]::IsPathRooted($InstallDir) -or $InstallDir -notmatch '^([A-Za-z]:\\|\\\\)') {
    throw "install: the install directory must be a filesystem path: $InstallDir"
}

$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    'X64' { 'x86_64' }
    'Arm64' { 'aarch64' }
    default { throw "install: no build for architecture $_" }
}
$asset = "mjolnir-$arch-pc-windows-msvc.zip"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $base = if ($Version -eq 'latest') {
        "https://github.com/$Repo/releases/latest/download"
    } else {
        "https://github.com/$Repo/releases/download/$Version"
    }
    foreach ($name in $asset, 'SHA256SUMS') {
        try {
            Invoke-WebRequest "$base/$name" -OutFile (Join-Path $tmp $name) -UseBasicParsing
        } catch {
            throw "install: cannot download $name from $Repo ($Version): $($_.Exception.Message)"
        }
    }

    $archive = Join-Path $tmp $asset
    $expected = Get-Content (Join-Path $tmp 'SHA256SUMS') |
        ForEach-Object { if ($_ -match "^([0-9a-f]{64})  $([regex]::Escape($asset))$") { $Matches[1] } }
    if (-not $expected -or (Get-FileHash $archive -Algorithm SHA256).Hash -ne $expected) {
        throw "install: checksum mismatch for $asset"
    }
    Expand-Archive $archive -DestinationPath $tmp
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    $exe = Join-Path $InstallDir 'mjolnir.exe'
    Copy-Item (Join-Path $tmp 'mjolnir.exe') $exe -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "installed $(& $exe --version) to $exe"
# Edit the registry value directly so entries like %USERPROFILE%\bin stay
# unexpanded; [Environment]::GetEnvironmentVariable would expand them.
$envKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
$userPath = $envKey.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if (($userPath -split ';') -notcontains $InstallDir) {
    $envKey.SetValue('Path', (@($userPath.TrimEnd(';'), $InstallDir) -ne '' -join ';'), 'ExpandString')
    # Deleting an unset variable broadcasts WM_SETTINGCHANGE, so new terminals
    # pick up the new PATH without signing out.
    [Environment]::SetEnvironmentVariable('MJOLNIR_INSTALL_REFRESH', $null, 'User')
    Write-Host "added $InstallDir to the user PATH; open a new terminal to use it"
}
$envKey.Close()
