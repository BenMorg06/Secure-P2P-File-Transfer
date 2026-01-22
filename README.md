# Secure Local File Transfer (Inspiration from LocalSend)

A secure, privacy preserving, pear-to-pear file transfer tool for local networks

This project is focussed on developing my practical cybersecurity knowledge through recreation of an existing app
It emphasises
- Secure Protocol Design
- End-to-End Encryption

---

## Project Status

This project is under active development

---

## Goals

- Secure peer-to-peer file transfer
- No server dependency
- End-to-End encryption
- Explicit and documented security assumptions

## System Architecture

```
Peer A <-- secure channel --> Peer B
  |                             |
File Writer                 File reader
Encryption                  Decryption
```

### Components

- Peer Discovery - finds peers on local network
- Handshake & Key Exchange - secure connection
- Secure Channel - end-to-end encryption
- File Transfer - handles chunking, retransmission, integrity

## Documentation

- 'docs/thread-model.md'
- 'docs/protocl-design.md'
- 'docs/attack-simulation.md'
- 'docs/crypto.md'

## Implementation

- Language: Python 3
