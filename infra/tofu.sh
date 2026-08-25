#!/usr/bin/env bash
# Run tofu with the Linode credential loaded.
#
#   infra/tofu.sh init
#   infra/tofu.sh plan
#   infra/tofu.sh apply
#
# Exists so the variables cannot be silently half-set: `source .env` alone does NOT export, and
# tofu only reads exported TF_VAR_*, so a plain source leaves it prompting for a token you
# thought you had set.
set -euo pipefail

cd "$(dirname "$0")"

# Order matters, and it is deliberate: an already-exported token wins over any file. Keeping
# one credential in one place beats copying it into every project that needs it, and a token
# that lives only in a shell session cannot be committed by accident.
#
#   export TF_VAR_linode_token=...          # best
#   LINODE_ENV_FILE=../other/infra/.env     # reuse another project's file, without duplicating it
#   infra/.env                              # last resort
# Local .env first, for this deployment's own settings. Then LINODE_ENV_FILE, for a credential
# that lives in another project - so the token exists in one place on disk rather than one per
# project, while the settings stay with the project they describe.
for pass in local foreign; do
  if [ "$pass" = local ]; then
    env_file=.env
    only_token=0
  else
    [ -n "${LINODE_ENV_FILE:-}" ] || continue
    [ -n "${TF_VAR_linode_token:-}" ] && continue
    env_file="$LINODE_ENV_FILE"
    only_token=1
  fi
  # A file belonging to another project contributes the credential and nothing else. Its
  # TF_VAR_region, TF_VAR_domain and friends are answers to that project's questions, and
  # letting them through would silently deploy this box wherever that one lives.
  if [ -f "$env_file" ]; then
    # Parsed, not sourced. `. ./.env` runs the file as shell, so an unquoted ssh-rsa key - which
    # contains spaces - is read as a command and fails with "AAAAB3...: command not found".
    # Parsing also means a config file cannot execute anything.
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in ''|'#'*) continue ;; esac
      key=${line%%=*}
      val=${line#*=}
      case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac   # ignore anything not a plain NAME=
      if [ "$only_token" = 1 ] && [ "$key" != TF_VAR_linode_token ]; then continue; fi
      val=${val%$'\r'}                                       # tolerate CRLF; this repo is edited on Windows
      case "$val" in
        \"*\") val=${val#\"}; val=${val%\"} ;;
        \'*\') val=${val#\'}; val=${val%\'} ;;
      esac
      [ -n "$val" ] || continue
      export "$key=$val"
    done < "$env_file"
    echo "loaded $([ "$only_token" = 1 ] && echo credential || echo settings) from $env_file" >&2
  fi
done

: "${TF_VAR_linode_token:?no Linode token. Export TF_VAR_linode_token, set LINODE_ENV_FILE, or create infra/.env from .env.example}"

# Read the public key from disk rather than making anyone paste a 700-character line. Under
# git-bash on Windows $HOME is the profile directory, so ~/.ssh/id_rsa.pub resolves to
# C:\Users\<you>\.ssh\id_rsa.pub - the same file ssh itself uses.
if [ -z "${TF_VAR_ssh_public_key:-}" ]; then
  for candidate in "${SSH_PUBLIC_KEY_FILE:-}" "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    [ -n "$candidate" ] && [ -f "$candidate" ] || continue
    TF_VAR_ssh_public_key="$(tr -d '\r\n' < "$candidate")"
    export TF_VAR_ssh_public_key
    echo "using ssh key from $candidate" >&2
    break
  done
fi

if [ -z "${TF_VAR_ssh_public_key:-}" ]; then
  echo "warning: no ssh public key found. cloud-init disables password login, so you would have" >&2
  echo "         NO way into the box. Generate one (ssh-keygen -t ed25519) before applying." >&2
fi

exec tofu "$@"
