# Install a mjolnir release binary on Windows (x64 or ARM64).
#
# Downloads with the GitHub CLI when it is logged in, otherwise through the
# GitHub API with a personal access token from GH_TOKEN or GITHUB_TOKEN. The
# token needs read access to the repository's contents. The archive is checked
# against the release's SHA256SUMS before anything is installed, and the
# install directory is added to the user PATH.
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
$token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($gh) { gh auth token *> $null }
    if ($gh -and $LASTEXITCODE -eq 0) {
        $tag = if ($Version -eq 'latest') { @() } else { @($Version) }
        gh release download @tag --repo $Repo --dir $tmp --pattern $asset --pattern SHA256SUMS
        if ($LASTEXITCODE -ne 0) { throw "install: gh could not download $asset from $Repo ($Version)" }
    } elseif ($token) {
        $headers = @{ Authorization = "Bearer $token"; 'X-GitHub-Api-Version' = '2022-11-28' }
        $api = "https://api.github.com/repos/$Repo/releases"
        $url = if ($Version -eq 'latest') { "$api/latest" } else { "$api/tags/$Version" }
        try {
            $release = Invoke-RestMethod $url -Headers ($headers + @{ Accept = 'application/vnd.github+json' })
        } catch {
            throw "install: no release $Version in $Repo, or the token cannot read it ($($_.Exception.Message))"
        }
        foreach ($name in $asset, 'SHA256SUMS') {
            $found = $release.assets | Where-Object name -EQ $name
            if (-not $found) { throw "install: release $($release.tag_name) has no $name" }
            Invoke-WebRequest $found.url -Headers ($headers + @{ Accept = 'application/octet-stream' }) `
                -OutFile (Join-Path $tmp $name) -UseBasicParsing
        }
    } else {
        throw "install: log in with 'gh auth login', or set GH_TOKEN to a personal access token"
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
