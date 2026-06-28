import asyncio
import logging
import sys
import socket
from pathlib import Path

sys.path.insert(0, "venv/kci-user-impersonation-client")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.crypto.truststore import TrustStore
from asyncua import ua

import time

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

USE_TRUST_STORE = True

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
    url = "opc.tcp://user1@127.0.0.1:4841/freeopcua/server/"

    # Create client and set security policies
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate = Path(cert_base / f"client-truststore/server.der")
    )

    # Load user pk and cert
    await client.load_client_certificate(user1_cert, extension="der")
    await client.load_private_key(user1_private_key, extension="pem")

    # Use trust store or not
    if USE_TRUST_STORE:
        trust_store = TrustStore([Path(cert_base / f"client-truststore")], [])
        await trust_store.load()
        validator = CertificateValidator(
            CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_SERVER, trust_store
        )
    else:
        validator = CertificateValidator(
            CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_SERVER
        )
    client.certificate_validator = validator

    try:
        # Standard client process
        async with client:
            objects = client.nodes.objects
            child = await objects.get_child(["1:ObjectUserCreated"])
            print("Child", child)

    except ua.UaError as exp:
        _logger.error(exp)

def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()

if __name__ == "__main__":
    main()
