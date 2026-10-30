output "stack" {
  value = "gateway"
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}

output "vm_id" {
  value = proxmox_virtual_environment_vm.gateway.vm_id
}

output "address" {
  value = local.ip
}
