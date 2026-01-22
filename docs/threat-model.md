
# Attackers

- Malicious or compromised devices on same local network
- Passive attacker, eavesdropper (packet sniffing)
- Active attacker, packet injection

## Capabilities

- Packet sniffing
- MITM
- Replay Attacks
# Assets

- File Contents
- Encryption Keys
- Peer Identities
# Out of Scope

- Physical access to endpoints
- Compromised OS

# Mitigations

| Threat    | Mitigation                                        |
| --------- | ------------------------------------------------- |
| MITM      | Authenticated key exchange, end-to-end encryption |
| Replay    | session IDs                                       |
| Tampering | AEAD encryption                                   |

