variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it."
  type        = string
  default     = "lab-gateway"
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
  description = "Public key the gateway VM accepts for the opaleye user (reached over the VPN; Ansible uses it)."
  type        = string
}

# Single source for the VM id, sizing, address and zone; the firewall rules come from the same file.
locals {
  plan    = jsondecode(file("${path.module}/../../../network/plan.json"))
  gateway = local.plan.gateway
  zone    = local.plan.zones["gateway"]
  ip      = local.plan.hosts["gateway"].ip
  prefix  = split("/", local.zone.cidr)[1]
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# The Guacamole gateway VM (#51). Own state and pool, so a target reset never rebuilds it and a rebuild of it never
# touches a target or Elastic. Cloned over the API from the template in this pool (scripts/make-gateway-template.sh).
# One NIC on the isolated gateway bridge: every path crosses the firewall, which allows only the operator in over
# the VPN, RDP to the attacker and SSH to the targets out.
resource "proxmox_virtual_environment_vm" "gateway" {
  name        = "opaleye-gateway"
  node_name   = var.node_name
  vm_id       = local.gateway.vm_id
  pool_id     = var.pool_id
  description = "Lab Guacamole gateway VM: browser GUI/terminal access to the attacker and targets; managed by OpenTofu"
  machine     = "q35"
  tags        = ["opaleye", "gateway"]
  started     = true
  on_boot     = false # lab shutdown powers guests off; the operator starts them

  operating_system {
    type = "l26"
  }

  agent {
    enabled = false # the template has no guest agent; Ansible reaches the VM over SSH
  }

  cpu {
    cores = local.gateway.vcpu
    type  = "host"
  }

  memory {
    dedicated = local.gateway.memory_mb
  }

  clone {
    vm_id        = local.gateway.template_vm_id
    datastore_id = var.datastore_id
    full         = true
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "virtio0"
    size         = local.gateway.os_disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge   = local.zone.bridge
    model    = "virtio"
    firewall = false # the routed firewall VM is the enforcement point
  }

  initialization {
    datastore_id = var.datastore_id
    dns {
      servers = [cidrhost(local.zone.cidr, 1)]
    }
    ip_config {
      ipv4 {
        address = "${local.ip}/${local.prefix}"
        gateway = cidrhost(local.zone.cidr, 1)
      }
    }
    user_account {
      username = "opaleye"
      keys     = [var.ssh_public_key]
    }
  }
}
