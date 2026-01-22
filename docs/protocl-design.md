# Protocol Assumptions

Network discovery is unauthenticated and untrusted
Security is established only after handshake completion
Replay attacks are mitigated through sequence numbers

# Data Flow
![[Drawing 2026-01-19 21.13.53.excalidraw]]
**Discovery**
- Sender
	- Displays list of discovered devices on same local network
- Receiver
	- Advertises device presence on local network through mDNS
- Data here is untrusted
- No sensitive data or keys exchanged

**Handshake**
- Sender
	- Selects device from list 
	- Initiates connection to receiver
	- Once approved
		- Sender and receiver perform ECDH key exchange
		- Shared session secret is derived using HKDF
		- Session Keys are established for encryption
- Receiver
	- Approves senders request to send data
**Transfer**
- File metadata and contents are encrypted end-to-end using session keys
- File is transferred in chunks over TCP
- Each chunk is encrypted and authenticated using AEAD
- Receiver verifies integrity before writing data to disk
**Close**
- Sender and receiver verify transaction is successful 
- Session keys and key material securely deleted
- TCP connection closed
- CLI terminated

Devices on the network should be displayed under aliases sharing the type of device only
Aliases should be two random words separated by hyphen and device type should be detailed to ensure sender can select correct device
e.g. Character-Lighter; MacBook Pro
# What is Encrypted?

File contents end-to-end
File metadata is encrypted
All application layer messages after handshake are encrypted

# What keys exist at what times?

ECDH key pairs generated during handshake
Shared session secret is derived via HKDF
Session encryption keys are established
All key material is securely wiped upon session close

# Threat -> Mitigation Map

![[Drawing 2026-01-19 21.44.52.excalidraw]]


