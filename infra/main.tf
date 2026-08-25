terraform {
  required_version = ">= 1.6"
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "linode" {
  token = var.linode_token
}

# The API requires a root password even when only key auth is used. Generated so no
# credential is ever typed into this repo. It still lands in state - see .gitignore.
resource "random_password" "witness_root" {
  length  = 32
  special = true
}

locals {
  ssh_keys = var.ssh_public_key == "" ? [] : [var.ssh_public_key]
}

# --- witness -----------------------------------------------------------------------------
# One box, two jobs.
#
# Today it is the Linux target the project does not otherwise have: internal/osq/osq_linux.go
# and internal/probe/truststore/store_unix.go have never executed anywhere, and phase 0 cannot
# exit until a clean network produces zero findings somewhere that is not the intercepted
# development machine.
#
# From phase 2 it becomes the witness proper: an independent vantage point on a different
# country and ASN, running the same probes against the same targets at the same moment, so
# that "the sensor sees X" can be checked against "someone outside sees Y".
#
# Debian is deliberate. It puts the trust store at /etc/ssl/certs/ca-certificates.crt with
# local additions under /usr/local/share/ca-certificates, which is the primary path in
# store_unix.go - so this box exercises the code that matters rather than an exotic layout.
resource "linode_instance" "witness" {
  label           = "mitmwatch-witness"
  region          = var.region
  type            = var.witness_type
  image           = var.image
  root_pass       = random_password.witness_root.result
  authorized_keys = local.ssh_keys
  tags            = ["mitmwatch"]

  metadata {
    user_data = base64encode(templatefile("${path.module}/cloud-init/witness.yaml", {
      # fail2ban must never ban the only address the firewall lets through. Without this,
      # three fat-fingered logins would lock the operator out of a box whose SSH is already
      # restricted to exactly one CIDR - recoverable only via Lish or another tofu apply.
      ssh_allow_cidrs = join(" ", var.ssh_allow_cidrs)
    }))
  }

  # cloud-init runs once, at first boot. Tofu still treats user_data as part of the instance,
  # so editing that file - even a comment - plans a destroy/create for a change that could not
  # take effect without a rebuild anyway. To adopt changes, rebuild deliberately:
  #   tofu apply -replace=linode_instance.witness
  lifecycle {
    ignore_changes = [metadata]
  }
}

# --- firewall ----------------------------------------------------------------------------
# Default DROP, and SSH restricted to var.ssh_allow_cidrs. A box whose entire purpose is to be
# a trustworthy second opinion should not be the most exposed host in the estate.
#
# Outbound stays ACCEPT, deliberately. This host's job is to reach arbitrary internet hosts and
# report what they look like from here; an egress allowlist would have to be widened for every
# target added to the config, and a stale one would silently turn a probe failure into a
# finding. The exposure that matters on a witness is inbound.
#
# LOCKOUT NOTE: restricting SSH to a residential address is safe because it is recoverable two
# ways that do not need SSH - the Lish console in the Linode manager, and re-running `tofu
# apply` with a wider ssh_allow_cidrs from anywhere, since tofu talks to the API and not to
# this box.
resource "linode_firewall" "witness" {
  label           = "mitmwatch-witness-fw"
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"
  linodes         = [linode_instance.witness.id]

  inbound {
    label    = "ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = var.ssh_allow_cidrs
    # No ipv6 key at all. sshd listens on v6, and a rule that matches only v4 sources leaves
    # v6 traffic matching nothing - so the DROP policy catches it. That is what stops the v6
    # internet reaching a port the v4 rule was carefully narrowed on. The provider rejects an
    # empty ipv6 list, so "omitted" is the only way to express it; the block below is how you
    # opt back in.
  }

  dynamic "inbound" {
    for_each = length(var.ssh_allow_cidrs_v6) > 0 ? [1] : []
    content {
      label    = "ssh-v6"
      action   = "ACCEPT"
      protocol = "TCP"
      ports    = "22"
      ipv6     = var.ssh_allow_cidrs_v6
    }
  }

  # Phase 2: the sensor dials the witness over pinned mTLS. Opened only when there is
  # something listening, because an open port with no service is a lie in a port scan.
  dynamic "inbound" {
    for_each = var.witness_port_open ? [1] : []
    content {
      label    = "witness-mtls"
      action   = "ACCEPT"
      protocol = "TCP"
      ports    = tostring(var.witness_port)
      ipv4     = var.witness_allow_cidrs
    }
  }
}
