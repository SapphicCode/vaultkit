# VaultKit

VaultKit, or `vk` as its command-line goes, is a toolbox of utilities designed to interface with [Hashicorp Vault](https://www.vaultproject.io/).

## Mission statement

VaultKit is not designed to replace [Vault Agent](https://www.vaultproject.io/docs/agent).
Vault Agent works great if you have to maintain secrets for long-running services, and update those secrets while the service is running.

This, on the contrary, is more of a scripting aid.
It'll help you conveniently authenticate with Vault, and provide secrets to your shell scripts.

## Features

- Unobtrusive authentication, with multiple methods
  - Token & `~/.vault-token`
    - Automated token renewal
  - AppRole authentication
  - Userpass authentication
- [Extensive configuration support](examples/vk.yml)
- More to come!
