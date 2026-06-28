import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, "/Users/tedap/Documents/Projects/FYP/exp211/python-opcua/models/vulnerability-models/race-condition/server")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua import ua

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

# Client's certificate and private key
cert_base = Path(__file__).parent
cert = Path(cert_base / f"client_cert.der")
private_key = Path(cert_base / f"client_key.der")

async def task(loop):
    client_app_uri = f"urn:open62541.unconfigured.application"
    url = "opc.tcp://user1:password1@Teds-MacBook-Pro.local:4841/freeopcua/server/"

    # Create client and set security policies
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"server_cert.der"),
        mode = 2
    )

    # Open channel, create session and read from/write to nodes
    import pdb; pdb.set_trace()
    try:
        async with client:
            await client.activate_session(username="admin", password="adminpassword")
            objects = client.nodes.objects
            
            # Validate if the object has been created
            child = await objects.get_child(["0:obj702"])

    except ua.UaError as exp:
        _logger.error(exp)

def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()

if __name__ == "__main__":
    main()
