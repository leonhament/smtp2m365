// Deploys smtp2m365 on a small Linux VM with a static public IP and a
// system-assigned managed identity. The managed identity is used for
// Let's Encrypt DNS-01 against Azure DNS and, after running
// scripts/Setup-ExchangeRbac.ps1, for sending through Exchange Online.

@description('Public DNS name devices connect to, e.g. smtp.contoso.com. It may be outside dnsZoneName; see azureRecordName.')
param hostname string

@description('Existing Azure DNS zone used for the gateway\'s DNS record and Let\'s Encrypt challenges, e.g. contoso.com.')
param dnsZoneName string

@description('Only used when hostname is not inside dnsZoneName: the record created in dnsZoneName. You then add two CNAMEs at the DNS provider of hostname (see the dnsRecordsToCreate output).')
param azureRecordName string = 'smtp2m365'

@description('Resource group of the Azure DNS zone (same subscription).')
param dnsZoneResourceGroup string

@description('Contact email for Let\'s Encrypt.')
param acmeEmail string

@description('Use the Let\'s Encrypt staging CA (untrusted certificates, generous rate limits).')
param acmeStaging bool = false

@description('Client IPs/CIDRs allowed to connect. Enforced by the NSG and by the gateway.')
param allowedSourceAddresses array

@description('Allowed sender patterns: exact address, "@domain" or "*".')
param allowedSenders array

@description('Denied sender patterns. Deny wins over allow.')
param deniedSenders array = []

@description('SMTP AUTH users as { users: [{ username, password_hash, allowed_senders? }] }. Create hashes with `smtp2m365 hash-password`. Without users the gateway relies on the IP allowlist alone.')
@secure()
param smtpUsers object = {}

@allowed(['smtp', 'graph'])
@description('smtp = SMTP client submission with XOAUTH2 (recommended); graph = Graph sendMail (4 MB limit).')
param exchangeMethod string = 'smtp'

param containerImage string = 'ghcr.io/leonhament/smtp2m365:latest'

param namePrefix string = 'smtp2m365'
param location string = resourceGroup().location
param vmSize string = 'Standard_B2ats_v2'
param adminUsername string = 'azureuser'

@description('SSH public key for the admin user. SSH is not opened in the NSG; use Bastion, JIT or Run Command.')
param sshPublicKey string

@description('Bearer token for the admin API (/api/stats, /api/events), reachable on the VM at http://127.0.0.1:8080.')
@secure()
param adminToken string = newGuid()

var users = smtpUsers.?users ?? []

var hostInZone = hostname == dnsZoneName || endsWith(hostname, '.${dnsZoneName}')
var recordName = !hostInZone ? azureRecordName : hostname == dnsZoneName ? '@' : substring(hostname, 0, length(hostname) - length(dnsZoneName) - 1)
var azureHostname = hostInZone ? hostname : '${azureRecordName}.${dnsZoneName}'
// Hostnames outside the Azure zone delegate the ACME challenge with a CNAME.
var challengeAlias = hostInZone ? '' : '_acme-challenge.${azureHostname}'

var gatewayConfig = {
  hostname: hostname
  listeners: [
    { addr: ':465', mode: 'implicit' }
    { addr: ':587', mode: 'starttls' }
  ]
  tls: {
    mode: 'acme'
    acme: {
      email: acmeEmail
      staging: acmeStaging
      challenge: 'dns-azure'
      challenge_alias: challengeAlias
      storage: '/data/certmagic'
      azure_dns: {
        subscription_id: subscription().subscriptionId
        resource_group: dnsZoneResourceGroup
      }
    }
  }
  exchange: { method: exchangeMethod }
  policy: {
    allowed_networks: allowedSourceAddresses
    require_auth: !empty(users)
    allowed_senders: allowedSenders
    denied_senders: deniedSenders
    check_header_from: true
  }
  users: users
  // Inside the container; published only on the VM's loopback interface.
  admin: { addr: ':8080', token: adminToken }
}

// JSON is valid YAML, so the config object is written as-is.
var cloudInit = '''
#cloud-config
package_update: true
packages:
  - docker.io
write_files:
  - path: /etc/smtp2m365/config.yaml
    permissions: '0600'
    encoding: b64
    content: {0}
  - path: /etc/systemd/system/smtp2m365.service
    content: |
      [Unit]
      Description=smtp2m365 gateway
      After=docker.service network-online.target
      Requires=docker.service
      [Service]
      Restart=always
      RestartSec=10
      ExecStartPre=-/usr/bin/docker rm -f smtp2m365
      ExecStartPre=/usr/bin/docker pull {1}
      ExecStart=/usr/bin/docker run --rm --name smtp2m365 -p 465:465 -p 587:587 -p 127.0.0.1:8080:8080 -v /etc/smtp2m365:/etc/smtp2m365:ro -v /var/lib/smtp2m365:/data {1}
      ExecStop=/usr/bin/docker stop smtp2m365
      [Install]
      WantedBy=multi-user.target
runcmd:
  - mkdir -p /var/lib/smtp2m365
  - chown 65532:65532 /var/lib/smtp2m365 /etc/smtp2m365/config.yaml
  - systemctl daemon-reload
  - systemctl enable --now smtp2m365
'''

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-smtp-tls'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: allowedSourceAddresses
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: ['465', '587']
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.60.0.0/24'] }
    subnets: [
      {
        name: 'gateway'
        properties: {
          addressPrefix: '10.60.0.0/27'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

resource pip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${namePrefix}-pip'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${namePrefix}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: pip.id }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: '${namePrefix}-vm'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: namePrefix
      adminUsername: adminUsername
      customData: base64(format(cloudInit, base64(string(gatewayConfig)), containerImage))
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            { path: '/home/${adminUsername}/.ssh/authorized_keys', keyData: sshPublicKey }
          ]
        }
        patchSettings: {
          patchMode: 'AutomaticByPlatform'
          assessmentMode: 'AutomaticByPlatform'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id }]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}

module dns 'dns.bicep' = {
  name: '${namePrefix}-dns'
  scope: resourceGroup(dnsZoneResourceGroup)
  params: {
    dnsZoneName: dnsZoneName
    recordName: recordName
    ipAddress: pip.properties.ipAddress
    principalId: vm.identity.principalId
  }
}

output publicIpAddress string = pip.properties.ipAddress
output managedIdentityPrincipalId string = vm.identity.principalId
output dnsRecordsToCreate string = hostInZone ? 'None, the record was created in Azure DNS.' : 'At the DNS provider of ${hostname}: "${hostname} CNAME ${azureHostname}" and "_acme-challenge.${hostname} CNAME ${challengeAlias}". The gateway waits for them before requesting a certificate.'
output nextStep string = 'Run scripts/Setup-ExchangeRbac.ps1 -ServicePrincipalObjectId ${vm.identity.principalId} to let the gateway send through Exchange Online.'
