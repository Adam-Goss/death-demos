variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it."
  type        = string
  default     = "lab-targets"
}

variable "node_name" {
  description = "Proxmox node that hosts the lab."
  type        = string
}

variable "datastore_id" {
  description = "Storage for lab disks. Never `local` (see docs/inventory/site-inventory.md)."
  type        = string
  default     = "iso-files"
}

variable "ssh_public_key" {
  description = "Public key the target VMs accept for the opaleye user (reached over the VPN; Ansible uses it)."
  type        = string
}

variable "rebuild_generation" {
  description = "Rebuild generation per target id. Raising it replaces that target's VM (reset by rebuild); scripts/target.sh owns the counter."
  type        = map(number)
  default     = {}
}

# Single source for the VM ids, sizing, addresses and zones; the firewall rules come from the same file.
# Only targets with a vm_id get a VM (t2 is reserved in the plan).
locals {
  plan = jsondecode(file("${path.module}/../../../network/plan.json"))
  targets = {
    for id, t in local.plan.targets : id => t if contains(keys(t), "vm_id")
  }
  zone_of = { for id, t in local.targets : id => local.plan.zones[local.plan.hosts[id].zone] }
  ip_of   = { for id, t in local.targets : id => local.plan.hosts[id].ip }
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# Recorded in encrypted state so re-apply is a provable no-op.
resource "terraform_data" "foundation" {
  input = {
    stack = "targets"
    pool  = var.pool_id
  }
}

# Changing the generation replaces the VM: the whole guest (OS, Docker volumes, uploads, app files) is rebuilt
# from pinned inputs, which is the reset contract (#8). Elastic, firewall and attacker are other stacks.
resource "terraform_data" "generation" {
  for_each = local.targets
  input    = lookup(var.rebuild_generation, each.key, 1)
}

# The vulnerable target. Cloned over the API from the template in this pool (scripts/make-target-template.sh):
# importing an image would need node SSH. One NIC on the target's isolated bridge, so every path crosses the
# firewall VM. No destroy guard here on purpose: a failed or used target is destroyed and rebuilt, never repaired.
resource "proxmox_virtual_environment_vm" "target" {
  for_each = local.targets

  name        = "opaleye-${each.key}"
  node_name   = var.node_name
  vm_id       = each.value.vm_id
  pool_id     = var.pool_id
  description = "Lab target ${each.key} (${each.value.catalogue}), rebuild generation ${lookup(var.rebuild_generation, each.key, 1)}; managed by OpenTofu"
  machine     = "q35"
  tags        = ["opaleye", "target", each.key]
  started     = true
  on_boot     = false # lab shutdown powers guests off; the operator starts them

  operating_system {
    type = "l26"
  }

  agent {
    enabled = false # the template has no guest agent; Ansible reaches the VM over SSH
  }

  cpu {
    cores = each.value.vcpu
    type  = "host"
  }

  memory {
    dedicated = each.value.memory_mb
  }

  clone {
    vm_id        = each.value.template_vm_id
    datastore_id = var.datastore_id
    full         = true
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "virtio0"
    size         = each.value.disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge   = local.zone_of[each.key].bridge
    model    = "virtio"
    firewall = false # the routed firewall VM is the enforcement point
  }

  initialization {
    datastore_id = var.datastore_id
    dns {
      servers = [cidrhost(local.zone_of[each.key].cidr, 1)]
    }
    ip_config {
      ipv4 {
        address = "${local.ip_of[each.key]}/${split("/", local.zone_of[each.key].cidr)[1]}"
        gateway = cidrhost(local.zone_of[each.key].cidr, 1)
      }
    }
    user_account {
      username = "opaleye"
      keys     = [var.ssh_public_key]
    }
  }

  lifecycle {
    replace_triggered_by = [terraform_data.generation[each.key]]
  }
}
