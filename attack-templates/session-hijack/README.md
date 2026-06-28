### Description
An attack on the Session Hijack vulnerability succeeds because the attacker can reopen a channel without having knowledge of previous channel keys. Since this attack runs in $Sign$ mode, the session token is visible in the network traces. The attacker has compromised the client's keys, so is able to reopen the session with the server, and use the stolen session token to execute any request as the user on the client.

### Instructions
1. Run the server. Update `attacker.py`, `client.py`, and `proxy.py` with the correct IP address and port number. The server should trust the legitimate client, the attacker's client, and user 1.
2. Generate keys and certificates for (Command looks for a `rsa_cert.cnf` in the current directory):
    - Server (Attacker steals)
    - Client
    - User 1 (Authorised user)
    - User 2 (Dummy user)
```bash
sh ../generate_key_cert_sh server
```

3. Run the proxy, specifying the attacker's port.
```bash
python3 proxy.py 61000
```

4. Run the client, as long as it stays online attack will succeed. User on the client creates and activates a session.
```bash
python3 client/client.py
```

6. Run the attacker once the the Session Token is leaked in the traces. Call with the source port, channel ID, token ID, and Session Token Identifier. The attacker has previously compromised the client's private key.
```bash
python3 attacker/attacker.py 61000 1 1 "936ca46c-bb39-0e11-3f13-0160e05e6566"
```

7. Proxy allows the attacker to take over the connection, and by reusing the specified Session Token, can execute arbitrary commands as the user.
