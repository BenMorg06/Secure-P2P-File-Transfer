# Algorithms Used


| Purpose      | Algorithm                |
| ------------ | ------------------------ |
| Key Exchange | ECDH (Ephemeral)         |
| Encryption   | AES-256-GCM              |
| Integrity    | Authenticated Encryption |
| Hashing      | SHA-256                  |
## Rationale

AES-GCM proved Confidentiality and Integrity
Ephemeral keys ensure forward secrecy
No long-term shared secrets stored on disk