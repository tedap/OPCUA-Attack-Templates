### Description
An attack on the KCI: User Impersonation vulnerability succeeds because the client's identity is not attached to the user's signature in the $ActivateSession$ request. Since the attacker has compromised the server's long term keys, they can pretend to be the server, forge a $OpenSecureChannelResponse$ and $CreateSessionResponse$ to the legitimate client to get the user's signature of the signature and reused nonce. The attacker can use this to activate the session on the server as the impersonated user.

### Instructions
1. Server runs. Needs to trust the attacker's client, legitimate client, and user 1.

2. Generate keys and certificates for (Command looks for a `rsa_cert.cnf` in the current directory):
    - Server (Attacker steals)
    - Attacker (as a client)
    - Client
    - User 1 (on the Client)

```bash
sh ../generate_key_cert_sh server
```

3. Run the attacker impersonating the server (port 4041).
```bash
python3 attacker/attacker-server.py
```

4. Run the attacker client that creates a channel and a session but hits a breakpoint before activating. It dumps the nonce the server provides to `nonce.txt`.
```bash
python3 attacker/attacker-client.py
```

5. Simulate the legitimate client which connects to the attacker's server. Attacker uses the nonce in `nonce.txt`, client replies with the user signature, which the attacker writes to `usertoken.txt`.
```bash
python3 client/client.py
```

6. Let the attacker continue running by pressing `c`. It reads in the user signature from `usertoken.txt`, and activates the session which the server accepts. The attacker can now execute any requests as user 1, despite not having access to their private key.