// A record for the gateway plus DNS Zone Contributor for its managed
// identity, so it can answer Let's Encrypt DNS-01 challenges.

param dnsZoneName string
param recordName string
param ipAddress string
param principalId string

var dnsZoneContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'befefa01-2a29-4197-83a8-272ff33ce314')

resource zone 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: dnsZoneName
}

resource a 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: zone
  name: recordName
  properties: {
    TTL: 300
    ARecords: [{ ipv4Address: ipAddress }]
  }
}

resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: zone
  name: guid(zone.id, principalId, dnsZoneContributor)
  properties: {
    roleDefinitionId: dnsZoneContributor
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
