variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it."
  type        = string
  default     = "lab-elastic"
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
  description = "Public key the Elastic VM accepts for the opaleye user (reached over the VPN; Ansible uses it)."
  type        = string
}

# Single source for the VM id, sizing, address and zone; the firewall rules come from the same file.
locals {
  plan    = jsondecode(file("${path.module}/../../../network/plan.json"))
  elastic = local.plan.elastic
  zone    = local.plan.zones["elastic"]
  ip      = local.plan.hosts["elastic"].ip
  prefix  = split("/", local.zone.cidr)[1]
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# The evidence VM. Own state and pool: no target or firewall operation can address it, and nothing
# in this stack may destroy it (evidence deletion is a separate guarded command, not a Tofu destroy).
# Cloned over the API from the template in this pool (scripts/make-elastic-template.sh): importing an
# image would need node SSH. One NIC, on the isolated elastic bridge, so every path crosses the firewall.
resource "proxmox_virtual_environment_vm" "elastic" {
  name        = "opaleye-elastic"
  node_name   = var.node_name
  vm_id       = local.elastic.vm_id
  pool_id     = var.pool_id
  description = "Lab evidence store: Elasticsearch ${local.elastic.version}, Kibana, Fleet Server; managed by OpenTofu"
  machine     = "q35"
  tags        = ["opaleye", "elastic"]
  started     = true
  on_boot     = false # lab shutdown powers guests off; the operator starts them

  operating_system {
    type = "l26"
  }

  agent {
    enabled = false # the template has no guest agent; Ansible reaches the VM over SSH
  }

  cpu {
    cores = local.elastic.vcpu
    type  = "host"
  }

  memory {
    dedicated = local.elastic.memory_mb
  }

  clone {
    vm_id        = local.elastic.template_vm_id
    datastore_id = var.datastore_id
    full         = true
  }

  # OS disk (cloned from the template, grown here).
  disk {
    datastore_id = var.datastore_id
    interface    = "virtio0"
    size         = local.elastic.os_disk_gb
    file_format  = "raw"
  }

  # Elasticsearch data (/var/lib/elasticsearch).
  disk {
    datastore_id = var.datastore_id
    interface    = "virtio1"
    size         = local.elastic.data_disk_gb
    file_format  = "raw"
  }

  # Snapshot repository (/srv/es-snapshots): a second virtual disk so a corrupt data filesystem
  # does not take the snapshots with it. It is NOT separate hardware while the host has one pool of
  # storage: that risk is accepted in docs/inventory/site-inventory.md. Point `datastore_id` at a
  # NAS or second disk later without changing anything in the guest.
  disk {
    datastore_id = var.datastore_id
    interface    = "virtio2"
    size         = local.elastic.snapshot_disk_gb
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

  lifecycle {
    # Destroy guard. A plan that would delete or replace the VM (and its evidence disks) fails.
    # Failed applies are fixed by re-apply, then the documented manual path; never auto-destroy.
    prevent_destroy = true
  }
}
