# ipv4 is a SET, so it has no meaningful ordering. one() is right rather than tolist()[0]:
# with private_ip unset there is exactly one public address, and if that ever stops being
# true this fails loudly instead of silently picking an arbitrary member.
locals {
  witness_ip = one(linode_instance.witness.ipv4)
}

output "witness_ip" {
  description = "Public address of the witness box."
  value       = local.witness_ip
}

output "ssh" {
  description = "How to reach it."
  value       = "ssh root@${local.witness_ip}"
}

output "next_steps" {
  value = <<-EOT
    Root SSH is disabled on this box. Connect as ops, which has passwordless sudo and the
    same key:  ssh ops@${local.witness_ip}

    1. Deploy the binary:
         GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mitmwatch-linux-amd64 ./cmd/mitmwatch
         scp mitmwatch-linux-amd64 ops@${local.witness_ip}:/tmp/mitmwatch
         ssh ops@${local.witness_ip} 'sudo install -m0755 /tmp/mitmwatch /usr/local/bin/mitmwatch'
         ssh ops@${local.witness_ip} 'sudo mitmwatch doctor'

    2. The clean-network baseline phase 0 needs. On an honest network with no interceptor,
       `mitmwatch check` must exit 0 after the learning window. Any finding here is a false
       positive and blocks the phase.

    3. The soak runs itself: mitmwatch-check.timer fires every 15 minutes from boot.
         ssh ops@${local.witness_ip} 'journalctl -u mitmwatch-check.service --since -24h'

    4. Verify the embedded root bundle from a host nobody is intercepting - the one check the
       development machine cannot do for itself, because its copy of the digest would arrive
       over the same connection that might be lying about it:
         ssh ops@${local.witness_ip} 'curl -fsS https://curl.se/ca/cacert.pem.sha256'
       Compare against `mitmwatch doctor` -> bundle sha256.

    5. If your address changes and SSH stops answering, that is the firewall doing its job.
       Recover without SSH either way: the Lish console in the Linode manager, or update
       TF_VAR_ssh_allow_cidrs in infra/.env and re-apply from anywhere.

    6. Phase 2 only: set witness_port_open = true and narrow witness_allow_cidrs.
  EOT
}
