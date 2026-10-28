output "stack" {
  value = "firewall"
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}

output "firewall_vm_id" {
  value = proxmox_virtual_environment_vm.firewall.vm_id
}

# vtnet index -> zone, for the OPNsense interface assignment.
output "nic_zones" {
  value = { for i, z in local.plan.nic_order : "vtnet${i}" => z }
}
