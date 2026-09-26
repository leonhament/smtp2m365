<#
.SYNOPSIS
    Grants the smtp2m365 gateway permission to send as a scoped set of
    mailboxes, using RBAC for Applications in Exchange Online.

.DESCRIPTION
    No API permission is consented in Entra ID. Instead, the gateway's
    service principal (its managed identity, or an app registration) gets an
    Exchange Online application role limited to the members of one group:

      -Method Smtp   -> role "Application SMTP.SendAsApp" (default)
      -Method Graph  -> role "Application Mail.Send"

    Make sure the app does NOT also hold Mail.Send / SMTP.SendAsApp in Entra
    ID: those grants are tenant-wide and would bypass the scope.

    Requires the ExchangeOnlineManagement module and Organization Management
    (or equivalent) rights. Role changes can take 30 minutes to 2 hours to
    take effect.

.EXAMPLE
    # Managed identity of the Azure VM (see the deployment output):
    $objectId = '<managedIdentityPrincipalId>'
    $appId    = az ad sp show --id $objectId --query appId -o tsv
    ./Setup-ExchangeRbac.ps1 -AppId $appId -ServicePrincipalObjectId $objectId `
        -SenderGroup smtp2m365-senders@contoso.com -EnableSmtpAuth
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $ServicePrincipalObjectId,

    # Mail-enabled security group or distribution group whose members the
    # gateway may send as.
    [Parameter(Mandatory)] [string] $SenderGroup,

    [ValidateSet('Smtp', 'Graph')] [string] $Method = 'Smtp',
    [string] $Name = 'smtp2m365',

    # SMTP method only: enable SMTP AUTH on each group member's mailbox,
    # which is required for SMTP client submission.
    [switch] $EnableSmtpAuth
)

$ErrorActionPreference = 'Stop'

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$role = if ($Method -eq 'Smtp') { 'Application SMTP.SendAsApp' } else { 'Application Mail.Send' }
$scopeName = "$Name senders"

# 1. Pointer to the Entra service principal.
$sp = Get-ServicePrincipal -Identity $AppId -ErrorAction SilentlyContinue
if (-not $sp) {
    if ($PSCmdlet.ShouldProcess($AppId, 'New-ServicePrincipal')) {
        $sp = New-ServicePrincipal -AppId $AppId -ObjectId $ServicePrincipalObjectId -DisplayName $Name
    }
}

# 2. Management scope: members of the sender group.
$group = Get-Group -Identity $SenderGroup
$filter = "MemberOfGroup -eq '$($group.DistinguishedName)'"
$scope = Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue
if (-not $scope) {
    if ($PSCmdlet.ShouldProcess($scopeName, 'New-ManagementScope')) {
        New-ManagementScope -Name $scopeName -RecipientRestrictionFilter $filter | Out-Null
    }
} elseif ($scope.RecipientFilter -ne $filter) {
    if ($PSCmdlet.ShouldProcess($scopeName, 'Set-ManagementScope')) {
        Set-ManagementScope -Identity $scopeName -RecipientRestrictionFilter $filter
    }
}

# 3. Scoped role assignment.
$assignmentName = "$Name - $role"
if (-not (Get-ManagementRoleAssignment -Identity $assignmentName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($assignmentName, 'New-ManagementRoleAssignment')) {
        New-ManagementRoleAssignment -Name $assignmentName -Role $role -App $AppId -CustomResourceScope $scopeName | Out-Null
    }
}

# 4. SMTP AUTH on the sending mailboxes (SMTP method only).
$members = Get-DistributionGroupMember -Identity $SenderGroup -ResultSize Unlimited |
    Where-Object RecipientTypeDetails -in 'UserMailbox', 'SharedMailbox'
if ($Method -eq 'Smtp') {
    foreach ($m in $members) {
        $cas = Get-CASMailbox -Identity $m.PrimarySmtpAddress
        if ($cas.SmtpClientAuthenticationDisabled -ne $false) {
            if ($EnableSmtpAuth) {
                if ($PSCmdlet.ShouldProcess($m.PrimarySmtpAddress, 'Enable SMTP AUTH')) {
                    Set-CASMailbox -Identity $m.PrimarySmtpAddress -SmtpClientAuthenticationDisabled $false
                }
            } else {
                Write-Warning "SMTP AUTH is not explicitly enabled for $($m.PrimarySmtpAddress); rerun with -EnableSmtpAuth or enable it manually."
            }
        }
    }
}

# 5. Verify (bypasses the permission cache).
foreach ($m in $members | Select-Object -First 5) {
    Test-ServicePrincipalAuthorization -Identity $AppId -Resource $m.PrimarySmtpAddress |
        Where-Object RoleName -eq $role |
        Select-Object RoleName, @{ n = 'Mailbox'; e = { $m.PrimarySmtpAddress } }, InScope
}

Write-Host "Done. The gateway may now send as members of $SenderGroup using $role. Allow up to 2 hours for the change to apply."
