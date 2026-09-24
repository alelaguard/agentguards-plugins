<#
AgentGuards hook for Codex on Windows - PowerShell port of agentguards_codex_hook.py.

Codex runs it through commandWindows in hooks/hooks.json:
    powershell -NoProfile -ExecutionPolicy Bypass -File agentguards_codex_hook.ps1 <Event>
Behaviour must match the Python hook exactly; tests/test_codex_ps1_parity.py runs both
against the same mock API. Keep this file ASCII (Windows PowerShell 5.1 reads a
BOM-less script as Windows-1252).
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# >>> AGENTGUARDS SHARED CORE (identical in claude/ and codex/ hooks; a test enforces it)
# Faithful PowerShell port of the Python hooks' shared helpers. Windows PowerShell
# 5.1 compatible. Notes that matter for parity with Python:
#   * Comparisons use -ceq/-ccontains and property lookups use Get-Prop: PowerShell
#     is case-INSENSITIVE by default, Python is not.
#   * This file is pure ASCII. 5.1 reads a BOM-less script as Windows-1252, so any
#     non-ASCII literal would be garbled; such characters are built from code points.
#   * Output is written as UTF-8 bytes; the console code page would garble it.

$Shield = [char]::ConvertFromUtf32(0x1F6E1) + [char]0xFE0F
$EmDash = [string][char]0x2014

function Get-HomeDir {
    $h = $env:USERPROFILE
    if ([string]::IsNullOrEmpty($h)) { $h = $env:HOME }
    if ([string]::IsNullOrEmpty($h)) { $h = [Environment]::GetFolderPath('UserProfile') }
    return $h
}

function Write-Utf8([System.IO.Stream]$Stream, [string]$Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}
function Write-Out([string]$Text) { Write-Utf8 ([Console]::OpenStandardOutput()) $Text }
function Write-Err([string]$Text) { Write-Utf8 ([Console]::OpenStandardError()) $Text }
function Write-JsonOut($Object) { Write-Out ($Object | ConvertTo-Json -Depth 20 -Compress) }

# --- loosely typed JSON, read the way Python reads it -------------------------------

# Exact (case-sensitive) property lookup; $Default when absent.
function Get-Prop($Obj, [string]$Name, $Default = $null) {
    # The unary comma stops PowerShell unrolling a one-element array into its element.
    if ($null -eq $Obj -or -not ($Obj -is [System.Management.Automation.PSCustomObject])) { return , $Default }
    foreach ($p in $Obj.PSObject.Properties) { if ($p.Name -ceq $Name) { return , $p.Value } }
    return , $Default
}
function Test-HasProp($Obj, [string]$Name) {
    if ($null -eq $Obj -or -not ($Obj -is [System.Management.Automation.PSCustomObject])) { return $false }
    foreach ($p in $Obj.PSObject.Properties) { if ($p.Name -ceq $Name) { return $true } }
    return $false
}
function Test-IsObject($v) { return ($v -is [System.Management.Automation.PSCustomObject]) }
function Test-IsList($v) { return ($v -is [System.Array]) -or ($v -is [System.Collections.IList] -and -not ($v -is [string])) }
function Test-IsNumber($v) {
    if ($null -eq $v) { return $false }
    # BigInteger by name: its assembly isn't loaded in Windows PowerShell 5.1.
    return ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [single] -or $v.GetType().FullName -ceq 'System.Numerics.BigInteger')
}

# Python truthiness of a decoded JSON value.
function Test-PyTruthy($v) {
    if ($null -eq $v) { return $false }
    if ($v -is [bool]) { return $v }
    if ($v -is [string]) { return $v.Length -gt 0 }
    if (Test-IsNumber $v) { return ([double]$v) -ne 0 }
    if (Test-IsList $v) { return @($v).Count -gt 0 }
    if (Test-IsObject $v) { return @($v.PSObject.Properties).Count -gt 0 }
    return $true
}

# Python str() for scalars; nested objects/lists become JSON (the Python side uses
# repr there - a formatting difference only; the content is still screened).
function ConvertTo-PyStr($v) {
    if ($null -eq $v) { return 'None' }
    if ($v -is [string]) { return $v }
    if ($v -is [bool]) { if ($v) { return 'True' } else { return 'False' } }
    if ($v -is [double]) {
        # Python writes a float with a fractional part: 2.0, not 2.
        $t = $v.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)
        if ($t -cmatch '^-?\d+$') { $t += '.0' }
        return $t
    }
    if (Test-IsNumber $v) { return ([System.Convert]::ToString($v, [System.Globalization.CultureInfo]::InvariantCulture)) }
    return ($v | ConvertTo-Json -Depth 20 -Compress)
}

# Python's result.get("decision", "allow"): "allow" only when the key is ABSENT. A
# null or non-string decision matches no verdict, so it takes the cautious path.
function Get-Decision($Result) {
    if (-not (Test-HasProp $Result 'decision')) { return 'allow' }
    $d = Get-Prop $Result 'decision'
    if ($d -is [string]) { return $d }
    return "`0non-string decision"
}

# A message field used verbatim when it's a non-empty string, else the default.
function Get-Message($Result, [string]$Field, [string]$Default) {
    $m = Get-Prop $Result $Field
    if ($m -is [string] -and $m.Length -gt 0) { return $m }
    return $Default
}

# First N code points (Python slicing), keeping surrogate pairs intact.
function Get-Shown([string]$Command) {
    $count = 0; $i = 0
    while ($i -lt $Command.Length) {
        if ([char]::IsHighSurrogate($Command[$i]) -and ($i + 1) -lt $Command.Length) { $i += 2 } else { $i += 1 }
        $count++
        if ($count -eq 500 -and $i -lt $Command.Length) { return $Command.Substring(0, $i) + '...' }
    }
    return $Command
}

function Test-Truthy([string]$Value) {
    if ($null -eq $Value) { return $false }
    return @('1', 'true', 'yes', 'on') -ccontains $Value.Trim().ToLowerInvariant()
}
function Test-FailOpen { return (Test-Truthy $env:AGENTGUARDS_FAIL_OPEN) }

function Get-InstallerKey {
    try {
        $path = Join-Path (Join-Path (Get-HomeDir) '.agentguards') 'credentials.json'
        if (-not (Test-Path -LiteralPath $path)) { return '' }
        $data = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        $key = Get-Prop $data 'api_key' ''
        if ($null -eq $key) { return '' }
        $key = ([string]$key).Trim()
        if ($key.StartsWith('ag_', [System.StringComparison]::Ordinal)) { return $key }
    } catch { }
    return ''
}

# --- HTTP ------------------------------------------------------------------------------

class AgentGuardsQuotaError : System.Exception {
    [string]$UserMessage
    AgentGuardsQuotaError([string]$m) : base($m) { $this.UserMessage = $m }
}
class AgentGuardsForbiddenError : System.Exception {
    AgentGuardsForbiddenError([string]$m) : base($m) { }
}
class AgentGuardsHttpError : System.Exception {
    [int]$StatusCode
    AgentGuardsHttpError([int]$code, [string]$m) : base($m) { $this.StatusCode = $code }
}

function Initialize-Tls {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
    } catch { }
    $bundle = $env:AGENTGUARDS_CA_BUNDLE
    if (-not [string]::IsNullOrWhiteSpace($bundle)) {
        $expanded = [Environment]::ExpandEnvironmentVariables($bundle.Trim())
        if ($expanded.StartsWith('~')) { $expanded = (Get-HomeDir) + $expanded.Substring(1) }
        # Verify against the appliance's own certificate: pinning, stricter than public roots.
        $pinned = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $expanded
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $cert, $chain, $errors)
            return ($cert.GetCertHashString() -ceq $pinned.GetCertHashString())
        }.GetNewClosure()
        return
    }
    if (Test-Truthy $env:AGENTGUARDS_TLS_NO_VERIFY) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
}

# POST JSON; returns the decoded response. 429 QUOTA_EXCEEDED and 403 are their own
# errors; any other failure (non-2xx, network, bad JSON) is an outage.
function Invoke-AgentGuards([string]$Path, $Payload, [int]$TimeoutSec = 10) {
    Initialize-Tls
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 20 -Compress))
    # HttpWebRequest, not Invoke-RestMethod: 5.1 would decode a charset-less response
    # as ISO-8859-1 and garble every non-ASCII byte of the block panel.
    $request = [System.Net.HttpWebRequest]::Create($script:AgentGuardsUrl + $Path)
    $request.Method = 'POST'
    $request.ContentType = 'application/json; charset=utf-8'
    $request.Accept = 'application/json'
    $request.Headers.Add('X-API-Key', $script:ApiKey)
    $request.Headers.Add('X-AgentGuards-Client', $script:ClientName)
    $request.Timeout = $TimeoutSec * 1000
    $request.ReadWriteTimeout = $TimeoutSec * 1000
    $status = 0; $text = ''
    try {
        $rs = $request.GetRequestStream(); $rs.Write($bodyBytes, 0, $bodyBytes.Length); $rs.Close()
        $response = $request.GetResponse()
        $status = [int]$response.StatusCode
    } catch [System.Net.WebException] {
        $we = $_.Exception
        while ($null -ne $we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
        $response = $null
        if ($null -ne $we) { $response = $we.Response }
        if ($null -eq $response) { throw }
        $status = [int]$response.StatusCode
    }
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd(); $reader.Close(); $response.Close()
    if ($status -eq 429) {
        try { $b = $text | ConvertFrom-Json } catch { $b = $null }
        if ((Get-Prop $b 'error') -ceq 'QUOTA_EXCEEDED') {
            $m = Get-Message $b 'message' 'Request quota reached.'
            throw [AgentGuardsQuotaError]::new($m)
        }
    }
    if ($status -eq 403) {
        try { $b = $text | ConvertFrom-Json } catch { $b = $null }
        throw [AgentGuardsForbiddenError]::new((Get-Message $b 'detail' 'Forbidden'))
    }
    if ($status -lt 200 -or $status -gt 299) {
        throw [AgentGuardsHttpError]::new($status, "HTTP Error $status")
    }
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'empty response from AgentGuards' }
    return ($text | ConvertFrom-Json)
}

function Get-ErrorText($Err) {
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $Err = $Err.Exception }
    $e = $Err
    while ($e -is [System.Management.Automation.MethodInvocationException] -and $null -ne $e.InnerException) { $e = $e.InnerException }
    return $e.Message
}
function Get-Inner($Err) {
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $Err = $Err.Exception }
    $e = $Err
    while ($null -ne $e.InnerException -and -not ($e -is [AgentGuardsHttpError])) { $e = $e.InnerException }
    return $e
}

# Mirrors _unreachable_remedy.
function Get-UnreachableRemedy($Err) {
    $bundle = $env:AGENTGUARDS_CA_BUNDLE
    if (-not [string]::IsNullOrWhiteSpace($bundle)) {
        $bundle = $bundle.Trim()
        $expanded = [Environment]::ExpandEnvironmentVariables($bundle)
        if ($expanded.StartsWith('~')) { $expanded = (Get-HomeDir) + $expanded.Substring(1) }
        if (-not (Test-Path -LiteralPath $expanded)) {
            return ("AGENTGUARDS_CA_BUNDLE points at $bundle, which does not exist. Save the " +
                "appliance's certificate there first:`n" +
                "      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null " +
                "| openssl x509 > $bundle`n" +
                "Or unset AGENTGUARDS_CA_BUNDLE to go back to the public CA roots.")
        }
    }
    $inner = Get-Inner $Err
    $text = Get-ErrorText $Err
    if ($inner -is [System.Security.Authentication.AuthenticationException] -or $text -match 'trust relationship|remote certificate is invalid|CERTIFICATE_VERIFY_FAILED') {
        $b = [string][char]0x2022
        return ("The server's certificate is not trusted. A self-hosted appliance signs " +
            "its own certificate on first boot, so this is expected until you install " +
            "a real one.`n" +
            "  $b Best: install your own certificate at Settings -> TLS certificate, and " +
            "reach the appliance by the hostname it is issued for.`n" +
            "  $b Or pin the appliance's certificate:`n" +
            "      openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null " +
            "| openssl x509 > ~/.agentguards-appliance.pem`n" +
            "      export AGENTGUARDS_CA_BUNDLE=~/.agentguards-appliance.pem`n" +
            "  $b Evaluating on a private network: export AGENTGUARDS_TLS_NO_VERIFY=true")
    }
    if ($inner -is [AgentGuardsHttpError] -and $inner.StatusCode -eq 401) {
        return ("The API key was rejected. Check AGENTGUARDS_API_KEY matches a key on this " +
            "instance (Admin console -> API keys), and that AGENTGUARDS_URL points at " +
            "the right one. Do not use AGENTGUARDS_FAIL_OPEN for this $EmDash the service is " +
            "healthy and turning off screening would not fix the credential.")
    }
    return 'Set AGENTGUARDS_FAIL_OPEN=true to allow requests while the service is down.'
}

# --- command parsing (mirrors _segments / _resolve_binaries) ------------------------------

$Wrappers = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::Ordinal)
$Wrappers['sudo'] = @('-u', '-g', '-p', '-C', '-U', '-r', '-t', '-h')
$Wrappers['doas'] = @('-u', '-C')
$Wrappers['env'] = @('-u', '-C', '-S')
$Wrappers['timeout'] = @('-s', '-k', '--signal', '--kill-after')
$Wrappers['nohup'] = @()
$Wrappers['nice'] = @('-n', '--adjustment')
$Wrappers['ionice'] = @('-c', '-n', '-p', '-t')
$Wrappers['stdbuf'] = @('-i', '-o', '-e')
$Wrappers['command'] = @()
$Wrappers['xargs'] = @('-a', '-d', '-E', '-I', '-L', '-n', '-P', '-s', '--max-args')
$Wrappers['time'] = @('-o', '-f', '--output', '--format')
$Wrappers['setsid'] = @()
$Wrappers['unbuffer'] = @()
$Wrappers['watch'] = @('-n', '--interval')
$Wrappers['script'] = @('-c')
$Shells = @('sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'busybox')
$FetchBinaries = @('curl', 'wget', 'http', 'https', 'fetch', 'aria2c')

function Get-Segments([string]$Command) {
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Command) { $Command = '' }
    $remainder = [regex]::Replace($Command, '\$\(([^()]*)\)|`([^`]*)`', {
            param($m)
            $inner = $m.Groups[1].Value
            if ($inner -ceq '') { $inner = $m.Groups[2].Value }
            $parts.Add($inner)
            return ' '
        })
    foreach ($s in [regex]::Split($remainder, '\|\||&&|[|;&\n]')) { $parts.Add($s) }
    return , $parts
}

function Get-ResolvedBinaries([string]$Segment, [int]$Depth = 0) {
    $tokens = @($Segment.Trim() -split '\s+' | Where-Object { $_ -cne '' })
    $found = [System.Collections.Generic.List[string]]::new()
    $idx = 0
    while ($idx -lt $tokens.Count) {
        $token = $tokens[$idx]
        if ($token -cmatch '^[A-Za-z_][A-Za-z0-9_]*=') { $idx++; continue }
        $name = ($token -split '/')[-1]
        $found.Add($name)
        if (($Shells -ccontains $name) -and $Depth -lt 3) {
            for ($j = $idx + 1; $j -lt $tokens.Count - 1; $j++) {
                $t = $tokens[$j]
                if ($t -ceq '-c' -or ($t.StartsWith('-') -and $t.Substring(1).Contains('c'))) {
                    $nested = (($tokens[($j + 1)..($tokens.Count - 1)]) -join ' ').Trim([char[]]@('"', "'"))
                    foreach ($b in (Get-ResolvedBinaries $nested ($Depth + 1))) { $found.Add($b) }
                    break
                }
            }
            break
        }
        if (-not $Wrappers.ContainsKey($name) -or $Depth -ge 3) { break }
        $takesValue = $Wrappers[$name]
        $idx++
        while ($idx -lt $tokens.Count) {
            $arg = $tokens[$idx]
            if ($arg -ceq '--') { $idx++; break }
            if ($arg.StartsWith('-')) {
                $idx++
                if (($takesValue -ccontains $arg) -and $idx -lt $tokens.Count) { $idx++ }
                continue
            }
            if ($arg -cmatch '^\d+(\.\d+)?[smhd]?$') { $idx++; continue }
            break
        }
    }
    return , $found
}

function Get-CommandBinaries([string]$Command) {
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($seg in (Get-Segments $Command)) {
        foreach ($b in (Get-ResolvedBinaries $seg 0)) { $all.Add($b) }
    }
    # Emitted as elements: callers wrap it in @(...).
    return $all.ToArray()
}

function Test-FetchCommand([string]$Command) {
    foreach ($b in (Get-CommandBinaries $Command)) { if ($FetchBinaries -ccontains $b) { return $true } }
    return $false
}

# A shell command as text: a string, or an argv list joined (mirrors _command_text).
function Get-CommandText($Value) {
    if ($Value -is [string]) { return $Value }
    if (Test-IsList $Value) { return ((@($Value) | ForEach-Object { ConvertTo-PyStr $_ }) -join ' ') }
    return ''
}

# --- per-session approval cache (same file and format as the Python hooks) ----------------

function Get-NowSeconds { return [double]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) / 1000.0 }

function Get-SortedUnique($Items) {
    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($i in $Items) { if ($null -ne $i) { [void]$set.Add([string]$i) } }
    return , ([string[]]@($set))
}

# Session id -> @{ binaries = string[]; pending = Dictionary; ts = double }, v2 only.
function Read-Approvals {
    $out = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    try {
        if (-not (Test-Path -LiteralPath $script:ApprovalsPath)) { return , $out }
        $data = [System.IO.File]::ReadAllText($script:ApprovalsPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    } catch { return , $out }
    if (-not (Test-IsObject $data)) { return , $out }
    foreach ($p in $data.PSObject.Properties) {
        $e = $p.Value
        if (-not (Test-IsObject $e)) { continue }
        $v = Get-Prop $e 'v'
        if (-not (Test-IsNumber $v) -or [double]$v -ne 2) { continue }
        $pending = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::Ordinal)
        $pd = Get-Prop $e 'pending'
        if (Test-IsObject $pd) { foreach ($q in $pd.PSObject.Properties) { $pending[$q.Name] = [string[]]@($q.Value) } }
        $ts = Get-Prop $e 'ts' 0
        if (-not (Test-IsNumber $ts)) { $ts = 0 }
        $bins = Get-Prop $e 'binaries' @()
        $out[$p.Name] = @{ binaries = [string[]]@($bins); pending = $pending; ts = [double]$ts }
    }
    return , $out
}

function Write-Approvals($Data) {
    $now = Get-NowSeconds
    $obj = [ordered]@{}
    foreach ($sid in $Data.Keys) {
        $e = $Data[$sid]
        if (($now - $e.ts) -ge (7 * 24 * 3600)) { continue }
        $pending = [ordered]@{}
        foreach ($k in $e.pending.Keys) { $pending[$k] = [string[]]@($e.pending[$k]) }
        $obj[$sid] = [ordered]@{ v = 2; binaries = [string[]]@($e.binaries); pending = $pending; ts = $e.ts }
    }
    try {
        $dir = Split-Path -Parent $script:ApprovalsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $json = $obj | ConvertTo-Json -Depth 20 -Compress
        [System.IO.File]::WriteAllText($script:ApprovalsPath, $json, [System.Text.UTF8Encoding]::new($false))
    } catch { }
}

function Get-ApprovedBinaries([string]$SessionId) {
    if ([string]::IsNullOrEmpty($SessionId)) { return , ([string[]]@()) }
    $data = Read-Approvals
    if (-not $data.ContainsKey($SessionId)) { return , ([string[]]@()) }
    return , ([string[]]@($data[$SessionId].binaries))
}

function Get-CommandKey([string]$Command) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Command))
    return (([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()).Substring(0, 16)
}

# The user IS BEING ASKED about this exact command (mirrors _mark_pending).
function Set-Pending([string]$SessionId, [string]$Command) {
    if ([string]::IsNullOrEmpty($SessionId) -or [string]::IsNullOrEmpty($Command)) { return }
    $data = Read-Approvals
    $pending = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::Ordinal)
    $binaries = [string[]]@()
    if ($data.ContainsKey($SessionId)) {
        foreach ($k in $data[$SessionId].pending.Keys) { $pending[$k] = $data[$SessionId].pending[$k] }
        $binaries = $data[$SessionId].binaries
    }
    $pending[(Get-CommandKey $Command)] = Get-SortedUnique (Get-CommandBinaries $Command)
    $data[$SessionId] = @{ binaries = (Get-SortedUnique $binaries); pending = $pending; ts = (Get-NowSeconds) }
    Write-Approvals $data
}

# The command ran; if a human was asked about it, it was approved (mirrors _redeem_pending).
function Complete-Pending([string]$SessionId, [string]$Command) {
    if ([string]::IsNullOrEmpty($SessionId) -or [string]::IsNullOrEmpty($Command)) { return }
    $data = Read-Approvals
    if (-not $data.ContainsKey($SessionId)) { return }
    $entry = $data[$SessionId]
    $key = Get-CommandKey $Command
    if (-not $entry.pending.ContainsKey($key)) { return }
    $bins = $entry.pending[$key]
    $pending = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $entry.pending.Keys) { if ($k -cne $key) { $pending[$k] = $entry.pending[$k] } }
    $data[$SessionId] = @{ binaries = (Get-SortedUnique (@($entry.binaries) + @($bins))); pending = $pending; ts = (Get-NowSeconds) }
    Write-Approvals $data
}

function Test-AllApproved($Binaries, [string]$SessionId) {
    $list = @($Binaries)
    if ($list.Count -eq 0) { return $false }
    $approved = Get-ApprovedBinaries $SessionId
    foreach ($b in $list) { if (-not ($approved -ccontains $b)) { return $false } }
    return $true
}

# --- scan-result helpers ----------------------------------------------------------------

$PiiChecks = @('presidio', 'pii_detection', 'secret_detection')

# Python: [c for c in checks if not c.get("passed", True)] - absent passes; any falsy fails.
function Get-FailingChecks($Result) {
    $failing = @()
    $checks = Get-Prop $Result 'checks'
    if (-not (Test-PyTruthy $checks) -or -not (Test-IsList $checks)) { return , $failing }
    foreach ($c in $checks) {
        if (-not (Test-IsObject $c)) { continue }
        if ((Test-HasProp $c 'passed') -and -not (Test-PyTruthy (Get-Prop $c 'passed'))) { $failing += , $c }
    }
    return , $failing
}
function Test-OnlyPiiFailed($Result) {
    $failing = Get-FailingChecks $Result
    if ($failing.Count -eq 0) { return $false }
    foreach ($c in $failing) { if (-not ($PiiChecks -ccontains (Get-Prop $c 'check_name'))) { return $false } }
    return $true
}
function Get-RedactedTypes($Result) {
    $types = [System.Collections.Generic.List[string]]::new()
    foreach ($c in (Get-FailingChecks $Result)) {
        $md = Get-Prop $c 'metadata'
        $list = Get-Prop $md 'pii_types'
        if (-not (Test-PyTruthy $list)) { continue }
        foreach ($t in @($list)) { $s = ConvertTo-PyStr $t; if (-not $types.Contains($s)) { $types.Add($s) } }
    }
    return $types.ToArray()
}

function Read-Event {
    # stdin as UTF-8 explicitly: the console's input code page would corrupt non-ASCII.
    $reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8)
    $raw = $reader.ReadToEnd(); $reader.Close()
    try { $evt = $raw | ConvertFrom-Json } catch { return $null }
    if (-not (Test-IsObject $evt)) { return $null }
    return $evt
}
# <<< AGENTGUARDS SHARED CORE

# --- Codex-specific ---------------------------------------------------------------------

$script:ClientName = 'codex/ps1'
# os.getenv(name, default): the default applies only when UNSET, as in the Python hook.
$script:AgentGuardsUrl = $env:AGENTGUARDS_URL
if ($null -eq $script:AgentGuardsUrl) { $script:AgentGuardsUrl = 'https://prod.agentguards.co' }
$script:AgentGuardsUrl = $script:AgentGuardsUrl.TrimEnd('/')
$script:ApprovalsPath = Join-Path (Join-Path (Get-HomeDir) '.codex') 'agentguards_session_approvals.json'

function Get-ApiKey {
    $key = $env:AGENTGUARDS_API_KEY
    if ($null -ne $key) { $key = $key.Trim() }
    if (-not [string]::IsNullOrEmpty($key)) { return $key }
    $tokenFile = Join-Path (Join-Path (Get-HomeDir) '.codex') 'agentguards_token'
    if (Test-Path -LiteralPath $tokenFile) {
        $token = ([System.IO.File]::ReadAllText($tokenFile, [System.Text.Encoding]::UTF8)).Trim()
        # an empty/blanked token file must not hide the installer's key
        if ($token.Length -gt 0) { return $token }
    }
    return (Get-InstallerKey)
}
$script:ApiKey = Get-ApiKey

$DefaultCommandPanel = "$Shield [AgentGuards] Command blocked`nDecision: deny`nReason: policy - flagged by AgentGuards guardrails`nSeverity: high"

function Exit-Continue { exit 0 }

function Exit-BlockPrompt([string]$Reason) {
    Write-JsonOut ([ordered]@{ decision = 'block'; reason = $Reason })
    exit 0
}

# PostToolUse block: decision "block" makes Codex replace the tool result before the
# model sees it.
function Exit-BlockOutput([string]$Reason) {
    Write-JsonOut ([ordered]@{
            decision           = 'block'
            reason             = $Reason
            hookSpecificOutput = [ordered]@{
                hookEventName     = 'PostToolUse'
                additionalContext = "AgentGuards withheld fetched web content: $Reason"
            }
        })
    exit 0
}

# The sanitised page goes back through decision "block" - the one channel Codex
# honours. updatedMCPToolOutput is parsed but unsupported and would fail OPEN.
function Exit-RedactOutput([string]$Redacted, $PiiTypes) {
    $what = ''
    if (@($PiiTypes).Count -gt 0) { $what = ' (' + (@($PiiTypes) -join ', ') + ')' }
    Write-JsonOut ([ordered]@{
            decision           = 'block'
            reason             = "$Redacted`n`n[AgentGuards redacted sensitive values$what from this content. The rest of the result is intact and safe to use.]"
            hookSpecificOutput = [ordered]@{
                hookEventName     = 'PostToolUse'
                additionalContext = "AgentGuards redacted sensitive values$what from the fetched content. The remaining content is intact $EmDash use it normally."
            }
        })
    exit 0
}

# Codex's PreToolUse rejects permissionDecision "ask"; returning no decision lets
# Codex's own approval_policy decide. The panel goes to stderr for the hook log.
function Exit-Ask([string]$Reason) {
    Write-Err $Reason
    exit 0
}

function Exit-Deny([string]$Reason) {
    Write-JsonOut ([ordered]@{
            hookSpecificOutput = [ordered]@{
                hookEventName            = 'PreToolUse'
                permissionDecision       = 'deny'
                permissionDecisionReason = $Reason
            }
        })
    exit 0
}

function Exit-PermissionAllow {
    Write-JsonOut ([ordered]@{
            hookSpecificOutput = [ordered]@{
                hookEventName = 'PermissionRequest'
                decision      = [ordered]@{ behavior = 'allow' }
            }
        })
    exit 0
}

function Exit-PermissionDeny([string]$Message) {
    Write-JsonOut ([ordered]@{
            hookSpecificOutput = [ordered]@{
                hookEventName = 'PermissionRequest'
                decision      = [ordered]@{ behavior = 'deny'; message = $Message }
            }
        })
    exit 0
}

function Get-ToolResponseText($Evt) {
    $response = Get-Prop $Evt 'tool_response'
    if ($response -is [string]) { return $response }
    if (Test-IsObject $response) {
        foreach ($k in @('output', 'stdout', 'content', 'text', 'result')) {
            $v = Get-Prop $response $k
            if ($v -is [string] -and $v.Length -gt 0) { return $v }
        }
        return ($response | ConvertTo-Json -Depth 20 -Compress)
    }
    return ''
}

function Invoke-WebScan([string]$Content) {
    if ($Content.Trim().Length -eq 0) { return }
    try {
        $result = Invoke-AgentGuards '/v1/guardrails/evaluate-input' ([ordered]@{ text = $Content; use_case = 'web_fetch'; channel = 'codex_hook' })
    } catch [AgentGuardsQuotaError] {
        Exit-BlockOutput "AgentGuards request quota reached: $($_.Exception.UserMessage) Fetched web content withheld."
    } catch {
        $err = Get-ErrorText $_
        if (Test-FailOpen) {
            Write-Err "AgentGuards: service unreachable ($err), allowing web content (AGENTGUARDS_FAIL_OPEN=true)"
            return
        }
        Exit-BlockOutput "AgentGuards unreachable ($err) $EmDash fetched web content withheld (fail-closed)."
    }
    $decision = Get-Decision $result
    $redacted = Get-Prop $result 'redacted_text'
    if ($decision -ceq 'redact' -and $redacted -is [string] -and $redacted.Trim().Length -gt 0 -and (Test-OnlyPiiFailed $result)) {
        Exit-RedactOutput $redacted (Get-RedactedTypes $result)
    }
    if ($decision -cne 'allow') {
        # Never append flagged_input here: it is an excerpt of the page we just
        # judged too dangerous to show.
        Exit-BlockOutput (Get-Message $result 'message' "$Shield [AgentGuards] Web content blocked`nDecision: block`nReason: policy - flagged by AgentGuards guardrails`nSeverity: high")
    }
}

function Invoke-UserPrompt($Evt) {
    $prompt = Get-Prop $Evt 'prompt' ''
    if (-not ($prompt -is [string])) { $prompt = ConvertTo-PyStr $prompt }
    if ($prompt.Trim().Length -eq 0) { Exit-Continue }
    try {
        $result = Invoke-AgentGuards '/v1/guardrails/evaluate-input' ([ordered]@{ text = $prompt; use_case = 'check' })
    } catch [AgentGuardsQuotaError] {
        Exit-BlockPrompt "[AgentGuards] Request quota reached: $($_.Exception.UserMessage)"
    } catch {
        $err = Get-ErrorText $_
        if (Test-FailOpen) {
            Write-Err "AgentGuards: service unreachable ($err), allowing prompt (AGENTGUARDS_FAIL_OPEN=true)"
            Exit-Continue
        }
        Exit-BlockPrompt "[AgentGuards] Prompt blocked: service unreachable ($err); the hook is fail-closed. $(Get-UnreachableRemedy $_)"
    }
    if (@('block', 'escalate', 'redact') -ccontains (Get-Decision $result)) {
        Exit-BlockPrompt (Get-Message $result 'message' "$Shield [AgentGuards] Prompt blocked`nReason: policy - flagged by AgentGuards guardrails")
    }
    Exit-Continue
}

function Get-ToolContext($Evt) {
    $toolInput = Get-Prop $Evt 'tool_input'
    if (-not (Test-PyTruthy $toolInput)) { $toolInput = $null }
    $raw = Get-Prop $toolInput 'command'
    $sid = Get-Prop $Evt 'session_id' ''
    if ($null -eq $sid) { $sid = '' }
    $tool = Get-Prop $Evt 'tool_name' ''
    if (-not (Test-PyTruthy $tool)) { $tool = 'shell' }
    return @{ Input = $toolInput; Raw = $raw; Command = (Get-CommandText $raw); Session = [string]$sid; Tool = $tool }
}

function Invoke-Authorize($Ctx) {
    return (Invoke-AgentGuards '/v1/actions/authorize' ([ordered]@{
                action     = 'shell_command'
                tool       = $Ctx.Tool
                parameters = [ordered]@{ command = $Ctx.Raw }
            }))
}

function Invoke-PreToolUse($Evt) {
    $ctx = Get-ToolContext $Evt
    if ($ctx.Command.Length -eq 0) { Exit-Continue }
    try {
        $result = Invoke-Authorize $ctx
    } catch [AgentGuardsQuotaError] {
        Exit-Deny "AgentGuards request quota reached: $($_.Exception.UserMessage)"
    } catch {
        $err = Get-ErrorText $_
        if (Test-FailOpen) {
            Write-Err "AgentGuards: service unreachable ($err), allowing tool call (AGENTGUARDS_FAIL_OPEN=true)"
            Exit-Continue
        }
        Exit-Deny "AgentGuards is unreachable ($err) and the hook is fail-closed. $(Get-UnreachableRemedy $_)"
    }
    $decision = Get-Decision $result
    $reason = Get-Message $result 'reason' $DefaultCommandPanel
    $shown = Get-Shown $ctx.Command
    if ($decision -ceq 'deny') { Exit-Deny "$reason`n`n    $shown" }
    if ($decision -ceq 'allow') { Exit-Continue }
    if (Test-AllApproved (Get-CommandBinaries $ctx.Command) $ctx.Session) { Exit-Continue }
    Exit-Ask "$reason`n`n    $shown"
}

# Fires only when Codex is already about to prompt the user. The ONLY place Codex
# may mark an approval pending: PreToolUse's no-decision path may run unasked.
function Invoke-PermissionRequest($Evt) {
    $ctx = Get-ToolContext $Evt
    if ($ctx.Command.Length -eq 0) { Exit-Continue }
    try {
        $result = Invoke-Authorize $ctx
    } catch {
        # The user is already being asked - don't hard-block their approval.
        Exit-Continue
    }
    $decision = Get-Decision $result
    $reason = Get-Message $result 'reason' $DefaultCommandPanel
    $shown = Get-Shown $ctx.Command
    if ($decision -ceq 'deny') { Exit-PermissionDeny "$reason`n`n    $shown" }
    if (Test-AllApproved (Get-CommandBinaries $ctx.Command) $ctx.Session) { Exit-PermissionAllow }
    Set-Pending $ctx.Session $ctx.Command
    if ($decision -cne 'allow') { Write-Err "$reason`n`n    $shown" }
    Exit-Continue
}

function Invoke-CodeScan($ToolInput) {
    $filePath = Get-Prop $ToolInput 'file_path'
    if (-not (Test-PyTruthy $filePath)) { $filePath = Get-Prop $ToolInput 'path' }
    $content = ''
    foreach ($k in @('patch', 'input', 'diff', 'content')) {
        $v = Get-Prop $ToolInput $k
        if ($v -is [string] -and $v.Length -gt 0) { $content = $v; break }
    }
    if ($content.Trim().Length -eq 0) { return }
    $label = 'file'
    if (Test-PyTruthy $filePath) { $label = ConvertTo-PyStr $filePath }
    Write-Err "AgentGuards: scanning $label for security issues..."
    try {
        # 8s: above the API's own 5s scan timeout, so a slow success isn't abandoned.
        $result = Invoke-AgentGuards '/v1/code/scan' ([ordered]@{ content = $content; file_path = $filePath }) 8
    } catch [AgentGuardsForbiddenError] {
        return
    } catch [AgentGuardsQuotaError] {
        Exit-BlockOutput "AgentGuards request quota reached: $($_.Exception.UserMessage) Write withheld."
    } catch {
        $err = Get-ErrorText $_
        if (Test-FailOpen) {
            Write-Err "AgentGuards: code scan unreachable ($err), allowing write (AGENTGUARDS_FAIL_OPEN=true)"
            return
        }
        Exit-BlockOutput "AgentGuards unreachable ($err) $EmDash write withheld (fail-closed)."
    }
    $decision = Get-Decision $result
    if ($decision -ceq 'block') { Exit-BlockOutput (Get-Message $result 'message' '[AgentGuards] Code scan blocked') }
    if ($decision -ceq 'warn' -and (Test-PyTruthy (Get-Prop $result 'message'))) { Write-Err (ConvertTo-PyStr (Get-Prop $result 'message')) }
}

function Invoke-PostToolUse($Evt) {
    $ctx = Get-ToolContext $Evt
    if ($ctx.Command.Length -gt 0 -and (Test-FetchCommand $ctx.Command)) {
        Invoke-WebScan (Get-ToolResponseText $Evt)
    }
    if ((Get-Prop $Evt 'tool_name') -ceq 'apply_patch') { Invoke-CodeScan $ctx.Input }
    # Asked about at PermissionRequest and then ran = approved.
    if ($ctx.Command.Length -gt 0) { Complete-Pending $ctx.Session $ctx.Command }
    Exit-Continue
}

function Invoke-Main([string]$EventType) {
    $evt = Read-Event
    if ($null -eq $evt) { Exit-Continue }
    if ($EventType -ceq 'PostToolUse') { Invoke-PostToolUse $evt }
    # Runs while the user is already being asked; a missing key defers, not blocks.
    if ($EventType -ceq 'PermissionRequest') { Invoke-PermissionRequest $evt }
    if ([string]::IsNullOrEmpty($script:ApiKey)) {
        $message = 'AgentGuards is not configured: save your ag_ token to ~/.codex/agentguards_token (or set AGENTGUARDS_API_KEY). The hook is fail-closed.'
        if ($EventType -ceq 'PreToolUse') { Exit-Deny $message }
        Exit-BlockPrompt $message
    }
    if ($EventType -ceq 'UserPromptSubmit') { Invoke-UserPrompt $evt }
    if ($EventType -ceq 'PreToolUse') { Invoke-PreToolUse $evt }
    Exit-Continue
}

# Dot-sourcing (tests) loads the functions without running the hook.
if ($MyInvocation.InvocationName -ne '.') {
    $eventType = ''
    if ($args.Count -gt 0) { $eventType = [string]$args[0] }
    Invoke-Main $eventType
}
