output "stack" {
  value = "analysis"
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}

output "vm_ids" {
  value = { for h, v in proxmox_virtual_environment_vm.analysis : h => v.vm_id }
}

output "addresses" {
  value = { for h in keys(local.hosts) : h => local.plan.hosts[h].ip }
}
