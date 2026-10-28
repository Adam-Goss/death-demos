output "stack" {
  value = terraform_data.foundation.output.stack
}

output "pool_id" {
  value = data.proxmox_virtual_environment_pool.this.pool_id
}
