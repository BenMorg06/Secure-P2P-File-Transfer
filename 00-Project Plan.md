
# Threat Model

## Who are the attackers?

Malicious or compromised devices on same local network
Passive attacker, eavesdropper (packet sniffing)
Active attacker, packet injection

## What needs to be protected?

File Contents - confidentiality & integrity
Device Identity - validity
Metadata (file name, size, type) - confidentiality
Transfer integrity (detect modification or corruption)

## What is out of scope?

Compromised OS - will result in compromised file transfer and breaks security
Physical Access - Attacker accesses files after transfer through device

# Initial Scope

Local Network only
One sender -> One receiver
One file at a time
Command-line interface (CLI)

# Networking Layer

**mDNS** for for device discovery
- Used to make device discoverable on local network
- May become security concern as mDNS is not inherently secure

**TCP** for transfer
- Provides reliable delivery
- All data is encrypted before transmission

# Encryption

## Key Exchange

ECDH key exchange using Curve25519
- Fresh key pair per session
- Provides forward secrecy
## Encryption

AES-GCM with AES-256
- Encryption before transmission
## Authentication

Receiver needs to approve incoming transmission
- To prevent unwanted file delivery
- Mitigates device impersonation

## Security Goals

- Confidentiality of transferred files
- Integrity of transferred data
- Minimal metadata leakage
- Resistance to LAN Man-In-The-Middle attacks
- Forward Secrecy
