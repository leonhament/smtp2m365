<#
.SYNOPSIS
    Shows or changes the configuration of an smtp2m365 gateway deployed with
    deploy/azure/main.bicep.

.DESCRIPTION
    The VM's config is baked into its first-boot data and cannot be changed
    by redeploying the template. This script changes it in place, through
    'az vm run-command':

      1. Reads /etc/smtp2m365/config.yaml from the VM.
      2. Applies the requested changes.
      3. Validates the result with the gateway itself ('check-config' in the
         target image) before touching the live config.
      4. Swaps the config, restarts the gateway and waits for it to listen.
         If it does not come up, the previous config and image are restored.
      5. Sets the NSG rule to exactly policy.allowed_networks, so the
         firewall and the gateway allowlist cannot drift apart.

    Requires PowerShell 7 and the Azure CLI (az login).

    New users get a random password, printed once. It is hashed on the VM
    (so no local Docker or Go is needed); it travels to the VM over the
    Azure control plane (TLS) and is never stored in clear text.

.EXAMPLE
    ./Update-GatewayConfig.ps1 -ResourceGroup rg-smtp2m365 -Show

.EXAMPLE
    # Your office IP changed
    ./Update-GatewayConfig.ps1 -ResourceGroup rg-smtp2m365 -AddAllowedNetwork 203.0.113.7 -RemoveAllowedNetwork 198.51.100.10

.EXAMPLE
    ./Update-GatewayConfig.ps1 -ResourceGroup rg-smtp2m365 -AddUser printer-floor3 -UserAllowedSender scanner@contoso.com

.EXAMPLE
    # Upgrade the gateway
    ./Update-GatewayConfig.ps1 -ResourceGroup rg-smtp2m365 -ImageTag 0.3.0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [string] $VmName = 'smtp2m365-vm',
    [string] $NsgName = 'smtp2m365-nsg',
    [string] $NsgRuleName = 'allow-smtp-tls',

    [switch] $Show,

    [string[]] $AddAllowedNetwork,
    [string[]] $RemoveAllowedNetwork,
    [string[]] $AddAllowedSender,
    [string[]] $RemoveAllowedSender,
    [string[]] $AddDeniedSender,
    [string[]] $RemoveDeniedSender,

    [string] $AddUser,
    # With -AddUser: restrict the new user to these senders.
    [string[]] $UserAllowedSender,
    [string] $RemoveUser,
    [string] $ResetPassword,

    [ValidateSet('Production', 'Staging')] [string] $AcmeCA,
    [string] $ImageTag
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Runs a bash script on the VM as root and returns its stdout.
function Invoke-Gateway([string] $Script) {
    # Internal plumbing must run even under -WhatIf.
    $file = New-TemporaryFile -WhatIf:$false
    try {
        Set-Content -Path $file -Value $Script -NoNewline -WhatIf:$false
        $json = az vm run-command invoke -g $ResourceGroup -n $VmName --command-id RunShellScript `
            --scripts "@$file" -o json --only-show-errors
        if ($LASTEXITCODE -ne 0) { throw "az vm run-command failed for $VmName in $ResourceGroup" }
    } finally {
        Remove-Item $file -ErrorAction SilentlyContinue -WhatIf:$false
    }
    $message = ($json | ConvertFrom-Json).value[0].message
    if ($message -notmatch '(?s)\[stdout\]\n(.*)\n\[stderr\]\n(.*)$') { throw "Unexpected run-command output: $message" }
    [pscustomobject]@{ Stdout = $Matches[1].Trim(); Stderr = $Matches[2].Trim() }
}

function ConvertTo-GzipBase64([string] $Text) {
    $out = [IO.MemoryStream]::new()
    $gz = [IO.Compression.GZipStream]::new($out, [IO.Compression.CompressionLevel]::Optimal)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Dispose()
    [Convert]::ToBase64String($out.ToArray())
}

function ConvertFrom-GzipBase64([string] $Base64) {
    $gz = [IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String($Base64)), [IO.Compression.CompressionMode]::Decompress)
    [IO.StreamReader]::new($gz, [Text.Encoding]::UTF8).ReadToEnd()
}

# Adds and removes items case-insensitively, keeping the original order.
function Update-List([string] $Name, $Current, [string[]] $Add, [string[]] $Remove) {
    $list = [Collections.Generic.List[string]]::new()
    foreach ($item in @($Current)) { if ($item) { $list.Add($item) } }
    foreach ($item in @($Add)) {
        if (-not $item) { continue }
        if ($list -contains $item) { Write-Warning "$Name already contains $item" }
        else { $list.Add($item); $script:changes.Add("$Name + $item") }
    }
    foreach ($item in @($Remove)) {
        if (-not $item) { continue }
        if ($list -notcontains $item) { Write-Warning "$Name does not contain $item" }
        else { [void]$list.RemoveAll({ param($x) $x -eq $item }); $script:changes.Add("$Name - $item") }
    }
    , [string[]]$list.ToArray()
}

function Test-SameSet($A, $B) {
    (@($A | Where-Object { $_ } | Sort-Object) -join ',') -eq (@($B | Where-Object { $_ } | Sort-Object) -join ',')
}

function New-Password {
    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(18)
    [Convert]::ToBase64String($bytes).Replace('+', 'x').Replace('/', 'y')
}

function Get-NsgPrefixes {
    $rule = az network nsg rule show -g $ResourceGroup --nsg-name $NsgName -n $NsgRuleName -o json --only-show-errors | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "Cannot read NSG rule $NsgName/$NsgRuleName" }
    @(@($rule.sourceAddressPrefix) + @($rule.sourceAddressPrefixes) | Where-Object { $_ })
}

function Write-Summary($Config, [string] $Image) {
    $users = @($Config.users | ForEach-Object {
            $s = if ($_['allowed_senders']) { " (senders: $($_['allowed_senders'] -join ', '))" } else { '' }
            "$($_.username)$s"
        })
    $ca = if ($Config.tls.acme.staging) { 'staging' } else { 'production' }
    [ordered]@{
        'Hostname'         = $Config.hostname
        'Image'            = $Image
        'Certificates'     = "$($Config.tls.mode) ($ca CA)"
        'Exchange method'  = $Config.exchange.method
        'Allowed networks' = $Config.policy.allowed_networks -join ', '
        'NSG source'       = (Get-NsgPrefixes) -join ', '
        'Require auth'     = $Config.policy.require_auth
        'Allowed senders'  = $Config.policy.allowed_senders -join ', '
        'Denied senders'   = $Config.policy['denied_senders'] -join ', '
        'Users'            = $users -join '; '
    } | Format-Table -HideTableHeaders -Wrap | Out-String | Write-Host
}

# 1. Read the live config and image.
Write-Host "Reading configuration from $VmName..."
$read = Invoke-Gateway @'
set -e
gzip -c /etc/smtp2m365/config.yaml | base64 -w0; echo
sed -n 's/^ExecStart=.* \([^ ]*\)$/\1/p' /etc/systemd/system/smtp2m365.service
'@
$lines = $read.Stdout -split "`n"
if ($lines.Count -lt 2) { throw "Could not read the gateway config: $($read.Stderr)" }
try {
    $config = ConvertFrom-GzipBase64 $lines[0] | ConvertFrom-Json -AsHashtable
} catch {
    throw "The config on the VM is not JSON (was it edited by hand as YAML?). This script only handles configs written by the Azure template."
}
$currentImage = $lines[1].Trim()

if ($Show) {
    Write-Summary $config $currentImage
    return
}

# 2. Apply changes.
$changes = [Collections.Generic.List[string]]::new()
$passwords = [ordered]@{}
$policy = $config.policy
$policy.allowed_networks = Update-List 'allowed_networks' $policy.allowed_networks $AddAllowedNetwork $RemoveAllowedNetwork
$policy.allowed_senders = Update-List 'allowed_senders' $policy.allowed_senders $AddAllowedSender $RemoveAllowedSender
$policy.denied_senders = Update-List 'denied_senders' $policy['denied_senders'] $AddDeniedSender $RemoveDeniedSender

$users = [Collections.Generic.List[object]]::new()
foreach ($u in @($config.users)) { if ($u) { $users.Add($u) } }
if ($RemoveUser) {
    if (-not ($users | Where-Object { $_.username -eq $RemoveUser })) { throw "User $RemoveUser does not exist" }
    [void]$users.RemoveAll({ param($u) $u.username -eq $RemoveUser })
    $changes.Add("user - $RemoveUser")
}
if ($AddUser) {
    if ($users | Where-Object { $_.username -eq $AddUser }) { throw "User $AddUser already exists (use -ResetPassword)" }
    $user = [ordered]@{ username = $AddUser; password_hash = $null }
    if ($UserAllowedSender) { $user.allowed_senders = [string[]]$UserAllowedSender }
    $users.Add($user)
    $passwords[$AddUser] = New-Password
    $changes.Add("user + $AddUser")
} elseif ($UserAllowedSender) {
    throw '-UserAllowedSender only applies together with -AddUser'
}
if ($ResetPassword) {
    if (-not ($users | Where-Object { $_.username -eq $ResetPassword })) { throw "User $ResetPassword does not exist" }
    $passwords[$ResetPassword] = New-Password
    $changes.Add("password reset for $ResetPassword")
}
$config.users = $users.ToArray()

if ($AcmeCA) {
    $staging = $AcmeCA -eq 'Staging'
    if ($config.tls.acme.staging -ne $staging) {
        $config.tls.acme.staging = $staging
        $changes.Add("Let's Encrypt CA -> $AcmeCA")
    }
}

$image = $currentImage
if ($ImageTag) {
    $image = $currentImage -replace ':[^:/]+$', ":$ImageTag"
    if ($image -ne $currentImage) { $changes.Add("image -> $image") }
}

$nsgPrefixes = Get-NsgPrefixes
$nsgInSync = Test-SameSet $nsgPrefixes $policy.allowed_networks
if ($changes.Count -eq 0 -and $nsgInSync) {
    Write-Host 'Nothing to change.'
    return
}
if ($changes.Count -gt 0) {
    Write-Host 'Changes:'
    $changes | ForEach-Object { Write-Host "  $_" }
}
if (-not $nsgInSync) {
    Write-Host "  NSG source -> $($policy.allowed_networks -join ', ') (was $($nsgPrefixes -join ', '))"
}
if (-not $PSCmdlet.ShouldProcess("$VmName in $ResourceGroup", 'Apply gateway configuration')) { return }

# 3 + 4. Hash new passwords, validate, swap, restart, verify (rollback on failure).
if ($changes.Count -gt 0) {
    if ($passwords.Count -gt 0) {
        Write-Host 'Hashing passwords on the gateway...'
        $list = ($passwords.Values | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }) -join ' '
        $hashed = Invoke-Gateway @"
set -e
docker pull -q '$image' >/dev/null
for p in $list; do echo "`$p" | base64 -d | docker run --rm -i --network none '$image' hash-password; done
"@
        $hashes = @($hashed.Stdout -split "`n" | Where-Object { $_ -like '$2*' })
        if ($hashes.Count -ne $passwords.Count) { throw "Hashing failed: $($hashed.Stderr)" }
        $i = 0
        foreach ($name in $passwords.Keys) {
            ($users | Where-Object { $_.username -eq $name }).password_hash = $hashes[$i++]
        }
    }

    $payload = ConvertTo-GzipBase64 ($config | ConvertTo-Json -Depth 20 -Compress)
    Write-Host 'Validating and applying on the gateway...'
    $apply = Invoke-Gateway @"
set -u
DIR=/etc/smtp2m365
UNIT=/etc/systemd/system/smtp2m365.service
NEW_IMAGE='$image'
OLD_IMAGE='$currentImage'
echo '$payload' | base64 -d | gunzip > `$DIR/config.yaml.new
chown 65532:65532 `$DIR/config.yaml.new && chmod 600 `$DIR/config.yaml.new

fail() { echo "RESULT: `$*"; rm -f `$DIR/config.yaml.new; exit 0; }
docker pull -q "`$NEW_IMAGE" >/dev/null 2>&1 || docker image inspect "`$NEW_IMAGE" >/dev/null 2>&1 || fail "cannot pull `$NEW_IMAGE"
ver=`$(docker run --rm --network none "`$NEW_IMAGE" version 2>/dev/null)
case "`$ver" in v0.1.*|v0.2.*) fail "`$NEW_IMAGE (`$ver) cannot validate configs; add -ImageTag 0.3.0 (or newer) to upgrade in the same step" ;; esac
# --network none: the check needs no network, and an image without
# check-config must not be able to start a second gateway.
out=`$(timeout 60 docker run --rm --network none -v `$DIR:`$DIR:ro "`$NEW_IMAGE" check-config -config `$DIR/config.yaml.new 2>&1)
[ "`$out" = "config OK" ] || fail "validation failed: `$out"

cp -p `$DIR/config.yaml `$DIR/config.yaml.bak
cp -p `$UNIT `$UNIT.bak
mv `$DIR/config.yaml.new `$DIR/config.yaml
sed -i "s#`$OLD_IMAGE#`$NEW_IMAGE#g" `$UNIT
systemctl daemon-reload

started() {
  since=`$1; ok=0
  for i in `$(seq 1 45); do
    sleep 2
    n=`$(journalctl -u smtp2m365 --since "@`$since" -o cat | grep -c '"msg":"listening"')
    [ "`$n" -ge 1 ] && { ok=1; break; }
  done
  sleep 5
  [ `$ok = 1 ] && systemctl is-active -q smtp2m365
}

since=`$(date +%s); systemctl restart smtp2m365
if started `$since; then echo "RESULT: applied"; exit 0; fi

echo "RESULT: gateway did not start, rolled back. Log:"
journalctl -u smtp2m365 --since "@`$since" -o cat | grep -v '^[0-9a-f]\{12\}: ' | tail -8
mv `$DIR/config.yaml.bak `$DIR/config.yaml
mv `$UNIT.bak `$UNIT
systemctl daemon-reload
since=`$(date +%s); systemctl restart smtp2m365
started `$since && echo "previous configuration is running again" || echo "WARNING: previous configuration did not start either"
"@
    Write-Host $apply.Stdout
    if ($apply.Stdout -notmatch 'RESULT: applied') { throw 'The configuration was not applied.' }
}

# 5. Firewall follows the gateway allowlist.
$networks = @($policy.allowed_networks)
if ($networks.Count -eq 0) {
    Write-Warning 'allowed_networks is empty: the gateway refuses every client. The NSG rule was left unchanged.'
} elseif (-not (Test-SameSet (Get-NsgPrefixes) $networks)) {
    Write-Host 'Updating NSG rule...'
    az network nsg rule update -g $ResourceGroup --nsg-name $NsgName -n $NsgRuleName `
        --source-address-prefixes @networks -o none --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'Updating the NSG rule failed; the gateway config was applied.' }
}

Write-Summary $config $image
foreach ($name in $passwords.Keys) {
    Write-Host "Password for ${name}: $($passwords[$name])   (shown once, store it now)" -ForegroundColor Yellow
}
