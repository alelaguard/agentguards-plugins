# AgentGuards installer for Windows.
#
#   irm https://agentguards.co/install.ps1 | iex
#
# Downloads agentguards.exe for this machine from the latest GitHub release,
# refuses it unless its SHA-256 matches the release's SHA256SUMS, installs it to
# %USERPROFILE%\.agentguards\bin (added to your user PATH), then runs
# `agentguards install`, which signs you in through your browser and protects
# every coding agent it finds.
#
# AGENTGUARDS_DOWNLOAD_BASE overrides where binaries come from (used by tests).
# AGENTGUARDS_INSTALL_ARGS passes options to `agentguards install` (e.g. "--yes").
#
# Everything runs inside a script block: `irm | iex` executes in the caller's own
# session, so bare variables and $ErrorActionPreference would leak into it, and a
# top-level `exit` would close their terminal.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is very slow with the progress bar

    $base = $env:AGENTGUARDS_DOWNLOAD_BASE
    if (-not $base) { $base = 'https://github.com/alelaguard/agentguards-plugins/releases/latest/download' }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $asset = "agentguards_windows_$arch.exe"
    $binDir = Join-Path $HOME '.agentguards\bin'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("agentguards-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        Write-Host "Downloading the AgentGuards installer for windows/$arch..."
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

        $expected = $null
        foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $expected = $parts[0].ToLower() }
        }
        if (-not $expected) { throw "no checksum for $asset in SHA256SUMS" }
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
        if ($expected -ne $actual) { throw "checksum mismatch for $asset - refusing to run it" }

        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        $exe = Join-Path $binDir 'agentguards.exe'
        Move-Item -Force (Join-Path $tmp $asset) $exe
        Write-Host "Installed $exe"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (($userPath -split ';') -contains $binDir)) {
            $newPath = if ($userPath) { "$userPath;$binDir" } else { $binDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Host "Added $binDir to your PATH (new terminals will see it)."
        }
        Write-Host ''
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }

    $installArgs = @('install')
    if ($env:AGENTGUARDS_INSTALL_ARGS) { $installArgs += ($env:AGENTGUARDS_INSTALL_ARGS -split '\s+' | Where-Object { $_ }) }
    & $exe @installArgs
}
