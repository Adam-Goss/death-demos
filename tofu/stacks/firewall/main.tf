variable "pool_id" {
  description = "Proxmox pool this stack is allowed to manage; the stack's token is scoped to it."
  type        = string
  default     = "lab-firewall"
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

variable "installer_iso_file_id" {
  description = "Pinned OPNsense installer ISO, e.g. iso-files:iso/OPNsense-26.1-dvd-amd64.iso; checksum recorded in the M2 runbook. Unused when cloning the template."
  type        = string
  default     = ""
}

variable "attach_installer" {
  description = "Attach the installer ISO. Set false (TF_VAR_attach_installer=false) once OPNsense is installed."
  type        = bool
  default     = true
}

variable "seed_iso_file_id" {
  description = "Config seed ISO already in the ISO store (scripts/opnsense_seed.py iso, uploaded out of band), e.g. iso-files:iso/opaleye-fw-seed.iso. Attached in the cdrom slot once the installer is detached; the OPNsense config importer reads conf/config.xml from it. Ignored when cloning the template. The id is not a secret; the ISO content is, so keep the store private."
  type        = string
  default     = ""
}

variable "firewall_template_vm_id" {
  description = "Seeded OPNsense template (scripts/make-firewall-template.sh, in pool lab-firewall); 0 = build from the installer ISO instead. Cloned over the API, so a rebuild needs no importer and no console. The template disk holds the seed's secrets (WireGuard private key, API secret hash, root hash): keep its pool private, and rebuild the template to rotate a secret."
  type        = number
  default     = 0
}

variable "probe_vms" {
  description = "Create throwaway A2 probe guests in the attacker, elastic and target zones. Destroy after A2."
  type        = bool
  default     = false
}

variable "probe_zones" {
  description = "Zones that get a probe guest. Drop \"elastic\" (TF_VAR_probe_zones='[\"attacker\",\"t1\",\"t2\"]') once the real Elastic VM owns that address (A3)."
  type        = list(string)
  default     = ["attacker", "elastic", "t1", "t2"]
}

variable "probe_template_vm_id" {
  description = "Probe template (scripts/make-probe-template.sh, in pool lab-firewall). Cloned over the API: importing an image would need node SSH."
  type        = number
  default     = 2100
}

variable "probe_ssh_public_key" {
  description = "Public key the probe guests accept (reached over the VPN)."
  type        = string
  default     = ""
}

# Single source of zones, bridges and addresses; the rules come from the same file.
locals {
  plan          = jsondecode(file("${path.module}/../../../network/plan.json"))
  from_template = var.firewall_template_vm_id > 0
  zones         = local.plan.zones
  probe_zones   = var.probe_zones
  probe_prefix  = { for z in ["attacker", "elastic", "t1", "t2"] : z => split("/", local.zones[z].cidr)[1] }
}

# Proves the stack token can read its own pool, and nothing else.
data "proxmox_virtual_environment_pool" "this" {
  pool_id = var.pool_id
}

# The only lab guest with a NIC on the home bridge (first NIC = WAN). All other NICs are
# isolated bridges with no host port, so every inter-zone path crosses this VM.
# NIC order is fixed by plan.nic_order (vtnet0..n) and must match the OPNsense interface
# assignment in plan.zones[*].iface.
resource "proxmox_virtual_environment_vm" "firewall" {
  name            = "opaleye-firewall"
  node_name       = var.node_name
  vm_id           = local.plan.firewall.vm_id
  pool_id         = var.pool_id
  description     = "Lab boundary firewall (OPNsense ${local.plan.firewall.version}); managed by OpenTofu"
  machine         = "q35"
  bios            = "seabios"
  on_boot         = false
  started         = true
  tags            = ["opaleye", "firewall"]
  stop_on_destroy = true

  operating_system {
    type = "other"
  }

  agent {
    enabled = false # os-qemu-guest-agent is a plugin installed after first boot
  }

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 4096
  }

  dynamic "clone" {
    for_each = local.from_template ? [1] : []
    content {
      vm_id        = var.firewall_template_vm_id
      datastore_id = var.datastore_id
      full         = true
    }
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "virtio0"
    size         = 20
    file_format  = "raw"
  }

  # Templated: the clone carries the seeded disk, so no cdrom. Otherwise installer first; after
  # install the out-of-band seed (if any); "none" = empty drive.
  dynamic "cdrom" {
    for_each = local.from_template ? [] : [1]
    content {
      file_id = (var.attach_installer ? var.installer_iso_file_id
      : var.seed_iso_file_id != "" ? var.seed_iso_file_id : "none")
      interface = "ide2"
    }
  }

  dynamic "network_device" {
    for_each = local.plan.nic_order
    content {
      bridge   = local.zones[network_device.value].bridge
      model    = "virtio"
      firewall = false # the routed firewall VM is the enforcement point; no Proxmox rules on its ports
    }
  }
}

# Throwaway guests that give A2 a source address in every zone. Not part of the lab proper.
resource "proxmox_virtual_environment_vm" "probe" {
  for_each  = var.probe_vms ? toset(local.probe_zones) : toset([])
  name      = "opaleye-probe-${each.key}"
  node_name = var.node_name
  pool_id   = var.pool_id
  tags      = ["opaleye", "a2-probe"]
  started   = true
  on_boot   = false

  operating_system {
    type = "l26"
  }

  agent {
    enabled = false
  }

  cpu {
    cores = 1
    type  = "host"
  }

  memory {
    dedicated = 512
  }

  clone {
    vm_id        = var.probe_template_vm_id
    datastore_id = var.datastore_id
    full         = true
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "virtio0"
    size         = 4
  }

  network_device {
    bridge   = local.zones[each.key].bridge
    model    = "virtio"
    firewall = false
  }

  initialization {
    datastore_id = var.datastore_id
    dns {
      servers = [cidrhost(local.zones[each.key].cidr, 1)]
    }
    ip_config {
      ipv4 {
        address = "${local.plan.hosts[each.key].ip}/${local.probe_prefix[each.key]}"
        gateway = cidrhost(local.zones[each.key].cidr, 1)
      }
    }
    user_account {
      username = "opaleye"
      keys     = [var.probe_ssh_public_key]
    }
  }
}
