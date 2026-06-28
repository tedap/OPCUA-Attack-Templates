### Description
An attack on the KCI: Session and User Confusion vulnerability succeeds because a client does not require knowledge of previous channel keys to reopen a channel. This allows an attacker to take over the $SecureChannel$, reuse a session token, and then allow the client to switch back to communication with the server, meaning multiple users possess the same session token, creating the confusion.

This attacks works in both $SignAndEncrypt$ and $Sign$ modes. The attacker has compromised the server's long-term keys.

### Instructions
1. Update `attacker.py`, `client.py`, and `proxy.py` with the correct server IP address and port.
2. Generate keys and certificates for (Command looks for a `rsa_cert.cnf` in the current directory):
    - Server (Attacker steals)
    - Client
    - User 1 (Authorised user)
    - User 2 (Dummy user)

```bash
sh ../generate_key_cert_sh server
```

3. Run proxy and attacker, both sit and listen to a client connecting to the server.
```bash
python3 proxy.py
python3 attacker/attacker.py
```

4. Run the client to simulate the client requests. Proxy automates the rest
```bash
python3 client/client.py
```