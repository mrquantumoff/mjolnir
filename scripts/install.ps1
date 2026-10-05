# Install a mjolnir release binary on Windows (x64 or ARM64).
#
# Downloads from the release's public URLs, so it needs no GitHub login or
# token. The release's SHA256SUMS must carry a valid signature by the release
# key below, the archive is checked against SHA256SUMS before anything is
# installed, and the install directory is added to the user PATH.
#
# usage: scripts/install.ps1 [-Version v0.1.0] [-InstallDir DIR] [-Repo owner/name]
#   Each parameter defaults to MJOLNIR_VERSION, MJOLNIR_INSTALL_DIR and
#   MJOLNIR_REPO, then to latest, %LOCALAPPDATA%\Programs\mjolnir and
#   mrquantumoff/mjolnir. MJOLNIR_RELEASE_KEY replaces the release key when
#   the repository is not the default one.
param(
    [string]$Version = $(if ($env:MJOLNIR_VERSION) { $env:MJOLNIR_VERSION } else { 'latest' }),
    [string]$InstallDir = $(if ($env:MJOLNIR_INSTALL_DIR) { $env:MJOLNIR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\mjolnir' }),
    [string]$Repo = $(if ($env:MJOLNIR_REPO) { $env:MJOLNIR_REPO } else { 'mrquantumoff/mjolnir' })
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Base64 of the SubjectPublicKeyInfo DER of the ECDSA P-256 key that signs
# SHA256SUMS; the same string as RELEASE_KEY in src/update.rs.
$releaseKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfCWNtshHxuxy4XyVXfa/O62yS79tJXqzlChtlVlBGHkHoF470qqwhXnhR/tVxC2a6H/M7miFldxmAlr8R/G1BA=='
if ($Repo -ne 'mrquantumoff/mjolnir' -and $env:MJOLNIR_RELEASE_KEY) {
    $releaseKey = $env:MJOLNIR_RELEASE_KEY
}

# True if $Signature, DER as openssl writes it, signs $Data under $Key, a
# key in the form of $releaseKey.
function Test-ReleaseSignature([string]$Key, [byte[]]$Data, [byte[]]$Signature) {
    try {
        # A P-256 SubjectPublicKeyInfo ends with the point's X and Y.
        $spki = [Convert]::FromBase64String($Key)
        $q = New-Object System.Security.Cryptography.ECPoint
        $q.X = $spki[-64..-33]
        $q.Y = $spki[-32..-1]
        $params = New-Object System.Security.Cryptography.ECParameters
        $params.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
        $params.Q = $q
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportParameters($params)
        # VerifyData takes r and s as two 32-byte big-endian halves, while DER
        # holds SEQUENCE { INTEGER r, INTEGER s }, each with no leading zero
        # unless its top bit is set.
        $rs = New-Object byte[] 64
        $at = 2
        foreach ($half in 0, 32) {
            $len = $Signature[$at + 1]
            $skip = [Math]::Max(0, $len - 32)
            [Array]::Copy($Signature, $at + 2 + $skip, $rs, $half + 32 - $len + $skip, $len - $skip)
            $at += 2 + $len
        }
        $ecdsa.VerifyData($Data, $rs, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        $false
    }
}

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
    foreach ($name in 'SHA256SUMS', 'SHA256SUMS.sig', $asset) {
        try {
            Invoke-WebRequest "$base/$name" -OutFile (Join-Path $tmp $name) -UseBasicParsing
        } catch {
            throw "install: cannot download $name from $Repo ($Version): $($_.Exception.Message)"
        }
    }

    $sums = [System.IO.File]::ReadAllBytes((Join-Path $tmp 'SHA256SUMS'))
    $signature = [System.IO.File]::ReadAllBytes((Join-Path $tmp 'SHA256SUMS.sig'))
    if (-not (Test-ReleaseSignature $releaseKey $sums $signature)) {
        throw 'install: SHA256SUMS does not match its signature SHA256SUMS.sig'
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
