variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it (and holds snapshot rights only here)."
  type        = string
  default     = "lab-analysis"
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
  description = "Public key the REMnux VM accepts for the opaleye user (reached through the gateway; Ansible and labops.py use it)."
  type        = string
}

variable "started" {
  description = "Power the analysis VMs on after apply. Off by default: they run only while the operator analyses a sample."
  type        = bool
  default     = false
}

# Single source for VM ids, sizing, addresses and the zone; the firewall rules come from the same file.
locals {
  plan   = jsondecode(file("${path.module}/../../../network/plan.json"))
  hosts  = local.plan.analysis.hosts
  zone   = local.plan.zones["analysis"]
  prefix = split("/", local.zone.cidr)[1]
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# The analysis VMs (#52): REMnux (Linux) and FLARE-VM (one isolated Windows VM; ADR 0002). Own state and pool, so nothing else is
# rebuilt with them and a reset (a Proxmox snapshot revert, labops.py analysis-reset) never needs this stack. Cloned over the
# API from templates in this pool (docs/runbooks/malware-analysis.md). One NIC on the isolated analysis bridge: every path
# crosses the firewall, which lets only the gateway in and only the ingestion endpoint out (plus the Internet while the
# operator has switched it on).
resource "proxmox_virtual_environment_vm" "analysis" {
  for_each = local.hosts

  name        = "opaleye-${each.key}"
  node_name   = var.node_name
  vm_id       = each.value.vm_id
  pool_id     = var.pool_id
  description = "Lab malware analysis VM (${each.key}); managed by OpenTofu. Revert with labops.py analysis-reset."
  machine     = "q35"
  tags        = ["opaleye", "analysis", each.key]
  started     = var.started
  on_boot     = false

  operating_system {
    type = each.value.os == "windows" ? "win11" : "l26"
  }

  agent {
    enabled = false # the templates carry no guest agent; operator access is SSH/RDP through the gateway
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
    interface    = each.value.os == "windows" ? "sata0" : "virtio0"
    size         = each.value.disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge   = local.zone.bridge
    model    = each.value.os == "windows" ? "e1000" : "virtio"
    firewall = false # the routed firewall VM is the enforcement point
  }

  # REMnux takes its address from cloud-init. The Windows template has its static address baked in (the runbook's one-off
  # build), because the template has no cloud-init.
  dynamic "initialization" {
    for_each = each.value.os == "linux" ? [1] : []
    content {
      datastore_id = var.datastore_id
      dns {
        servers = [cidrhost(local.zone.cidr, 1)]
      }
      ip_config {
        ipv4 {
          address = "${local.plan.hosts[each.key].ip}/${local.prefix}"
          gateway = cidrhost(local.zone.cidr, 1)
        }
      }
      user_account {
        username = "opaleye"
        keys     = [var.ssh_public_key]
      }
    }
  }

  # A revert changes the disk behind Tofu's back, and the operator powers the VMs: neither is drift to correct.
  lifecycle {
    ignore_changes = [started]
  }
}
