### Description
An attack on the Race Condition is possible as the same session token is used when the session is handed over to a new user. This means any requests from the previous user are still valid, and if delayed past the session handover, will still be accepted and executed by the server.

### Instructions
1. Run the server. Update `client.py`, `validation-client.py`, and `proxy.py` with the correct IP address and port number.
    - Server should support username password authentication.
    - Server should have two accounts: a regular user `user1`, and a privileged user `admin`. Update `client.py` and `validation-client.py` accordingly.
2. Generate keys and certificates for (Command looks for a `rsa_cert.cnf` in the current directory):
    - Server
    - Client

```bash
sh ../generate_key_cert_sh server
```

3. Run the proxy.
```bash
python3 proxy.py
```

4. Run the client
```bash
python3 attacker/client.py
```

5. On the proxy keep pressing enter to forward messages until the breakpoint is reached on the client. The unauthorised user on client saves a request to `msg.txt`.
6. Press `c` on the client to continue.
7. Press `s` on the proxy on the next message to swap in user 1's request.
8. The server accepts and executes user 1's request as the current user (admin).