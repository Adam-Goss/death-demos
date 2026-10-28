output "stack" {
  value = terraform_data.foundation.output.stack
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}

output "targets" {
  value = {
    for id, vm in proxmox_virtual_environment_vm.target : id => {
      vm_id      = vm.vm_id
      address    = local.ip_of[id]
      generation = lookup(var.rebuild_generation, id, 1)
    }
  }
}
