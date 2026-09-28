resource "azurerm_linux_virtual_machine_scale_set" "agents" {
  name                = "vmss-build-agents-dev"
  resource_group_name = "rg-ci-dev"
  sku                 = "Standard_D2s_v5"
  instances           = 3
}

resource "azurerm_linux_virtual_machine" "web2" {
  name = "vm-web-dev-2"
}
