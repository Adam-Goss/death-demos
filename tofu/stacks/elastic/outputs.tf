output "stack" {
  value = "elastic"
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}

output "vm_id" {
  value = proxmox_virtual_environment_vm.elastic.vm_id
}

output "address" {
  value = local.ip
}
