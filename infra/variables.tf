variable "linode_token" {
  description = "Linode API token. Supply via the environment (TF_VAR_linode_token), never a file - state and .tfvars are not places for a credential. Linodes: Read/Write and Firewalls: Read/Write is enough."
  type        = string
  sensitive   = true
}

# The witness must sit on a different country AND ASN from the network being watched,
# otherwise it corroborates the same upstream that may be doing the intercepting. Latency
# matters less than independence: the sync tick has a deadline, not a millisecond budget.
variable "region" {
  description = "Linode region id. Must NOT be the country the sensor lives in."
  type        = string
  default     = "us-east"
}

# g6-nanode-1 is Linode's smallest: 1 shared vCPU, 1GB, ~$5/mo. The witness runs the same
# canary probes as the sensor - five TLS handshakes and a few DNS lookups every five minutes -
# so this is generous, not tight.
variable "witness_type" {
  type    = string
  default = "g6-nanode-1"
}

variable "image" {
  description = "Debian puts the trust store where store_unix.go looks first, so this box exercises the primary path rather than an exotic one."
  type        = string
  default     = "linode/debian12"
}

variable "ssh_public_key" {
  description = "Public key installed for root. cloud-init disables password login, so without a key there is no way in at all. tofu.sh reads it off disk if this is empty."
  type        = string
  default     = ""
}

# Deny by default. An empty list means the firewall has no ACCEPT rule for SSH at all, so a
# forgotten value fails closed rather than publishing the port to the internet. Set the real
# value in infra/.env, which is gitignored - an operator's home address does not belong in a
# committed file, and it rots.
#
# Recoverable without SSH if the address changes: the Lish console in the Linode manager, or
# re-running `tofu apply` with a new value from anywhere, since tofu talks to the API.
variable "ssh_allow_cidrs" {
  description = "IPv4 CIDRs allowed to reach port 22. Empty means nobody - use the Lish console."
  type        = list(string)
  default     = []
}

variable "ssh_allow_cidrs_v6" {
  description = "IPv6 CIDRs allowed to reach port 22. Empty is correct unless you actually connect over v6: sshd listens on v6, so an empty list here is what stops the v6 internet reaching a port the v4 rule was narrowed on."
  type        = list(string)
  default     = []
}

variable "witness_port" {
  description = "Port the phase 2 witness listens on for pinned mTLS from the sensor."
  type        = number
  default     = 8443
}

variable "witness_port_open" {
  description = "Leave false until phase 2 puts a listener there. An open port with nothing behind it only widens the attack surface."
  type        = bool
  default     = false
}

variable "witness_allow_cidrs" {
  description = <<-EOT
    Which addresses may dial the witness port. Not the internet, and in practice not a single
    /32 either.

    A /32 is the tightest rule and it is the one that breaks: a residential line's address is
    rotated by the ISP, and when it moves the sensor is locked out of its own witness until a
    human notices. That happened here and cost 31 hours of the detector running with no outside
    opinion. Every automatic repair for it costs something worse - an open port, a cloud
    credential on the sensor, or a third party in the recovery path.

    So allowlist the ISP allocations the line actually draws from. It is a much larger set than
    one address and a much smaller one than the internet, it never goes stale, and it has no
    moving parts to fail. The firewall was only ever defence-in-depth: the witness authenticates
    by pinned mutual TLS with no CA, and that is unaffected either way.

    Find yours from the sensor, and include every allocation it has been seen in:
      whois "$(curl -s https://api.ipify.org)" | grep -iE '^(inetnum|netname)'

    Set it in infra/.env, which is gitignored - a public repo should not carry a map of which
    netblock its author's sensor lives in.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
