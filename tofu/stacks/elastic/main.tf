variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it."
  type        = string
  default     = "lab-elastic"
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# Recorded in encrypted state so re-apply is a provable no-op until real resources land.
resource "terraform_data" "foundation" {
  input = {
    stack = "elastic"
    pool  = var.pool_id
  }
}
