param location string = resourceGroup().location

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: 'vm-web-dev'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_D4s_v5' }
  }
}

resource dataDisk 'Microsoft.Compute/disks@2024-03-02' = {
  name: 'disk-web-dev-data'
  location: location
  sku: { name: 'Premium_LRS' }
  properties: { diskSizeGB: 256, creationData: { createOption: 'Empty' } }
}
