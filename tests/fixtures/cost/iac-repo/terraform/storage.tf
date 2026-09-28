resource "azurerm_storage_account" "logs" {
  name        = "stlogsdev"
  access_tier = "Hot"
}
