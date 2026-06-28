import asyncio
import logging
import sys
import socket
from pathlib import Path

sys.path.insert(0, "venv/session-hijack-client")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua import ua

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

# Client's certificate and private key
cert_base = Path(__file__).parent
cert = Path(cert_base / f"client.der")
private_key = Path(cert_base / f"client.pem")

# User 1 - the user to be impersonated
user1_cert = Path(cert_base / f"user-certificates/user1-cert.der")
user1_private_key = Path(cert_base / f"user-certificates/user1.pem")

async def task(loop):
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    # IP Address of the proxy
    url = "opc.tcp://user1@127.0.0.1:4840/freeopcua/server/"

    # Create client and set security policies
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"client-truststore/server.der"),
        # Sign-only mode
        mode = 2
    )

    # Load user pk and cert
    await client.load_client_certificate(user1_cert, extension="der")
    await client.load_private_key(user1_private_key, extension="pem")

    try:
        # Standard client process
        async with client:
            objects = client.nodes.objects
            try:
                child = await objects.get_child(["1:TestNode"])
                print("Child", child)
            except ua.UaError as exp:
                pass
            
            # Client gets put to sleep to keep alive while attacker hijacks
            await asyncio.sleep(100)

    except ua.UaError as exp:
        _logger.error(exp)

def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()

if __name__ == "__main__":
    main()
