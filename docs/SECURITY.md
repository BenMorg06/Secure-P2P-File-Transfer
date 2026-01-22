# Security Policy

This project implements a secure peer-to-peer file transfer protocol intended for educational and experimental use.
Modern cryptographic primitives are used, but the software has not undergone formal third-party security audit

## Supported Versions

## Security Guarantees

The project aims to provide
- End-to-end confidentiality of file contents
- Integrity and authenticity of transferred data
- Forward secrecy via ephemeral key exchange
- Protection against network attackers

## [[threat-model|Threat Model]]

Attackers assumed to be capable of
- Passive network sniffing
- Active message tampering
- Replay attacks

## ![[crypto|Cryptographic Design]]
No custom cryptographic primitives are implemented

## Known Limitations

- No protection against compromised endpoints
- No post-quantum cryptography

## Secure Usage Guidlines

- Use on trusted networks
- Do not reuse keys between sessions
- Do not use for highly sensitive or regulated data

## Reporting a vulnerability

If you discover a security issue, please report it via
Email: b_morgan04@outlook.com

Provide
- Description of the issue
- Steps to reproduce
- Potential Impact

## Security Testing

- Unit tests for cryptographic components
- Manual replay and tampering simulations
- Negative testing for malformed packets