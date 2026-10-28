# Elastic evidence VM (M3). Own state and pool; target/firewall operations cannot address it. Order 2.
# State is encrypted (OpenTofu native). The key provider comes from the TF_ENCRYPTION
# env var that scripts/lab.sh builds from the offline passphrase; it is never in the repo.
# With no key provider defined, init/plan fail closed instead of writing plaintext state.
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.84.1"
    }
  }

  backend "local" {
    path = "../../../.state/elastic.tfstate"
  }

  encryption {
    method "aes_gcm" "lab" {
      keys = key_provider.pbkdf2.lab
    }
    state {
      method   = method.aes_gcm.lab
      enforced = true
    }
    plan {
      method   = method.aes_gcm.lab
      enforced = true
    }
  }
}

# API token only. No ssh block: nothing here may need node SSH.
# Endpoint, token and TLS settings come from PROXMOX_VE_ENDPOINT / PROXMOX_VE_API_TOKEN /
# PROXMOX_VE_INSECURE in the environment.
provider "proxmox" {}
