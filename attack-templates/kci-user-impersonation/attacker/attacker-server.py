import asyncio
import sys
from pathlib import Path
import socket

import logging

sys.path.insert(0, "venv/kci-user-impersonation-attacker")
from asyncua import Server
from asyncua import ua
from asyncua.server.user_managers import CertificateUserManager
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.crypto.truststore import TrustStore

logging.basicConfig(level=logging.INFO)

USE_TRUST_STORE = True

async def main():
    # Server's certificate and private key
    cert_base = Path(__file__).parent
    server_cert = Path(cert_base / "server.der")
    server_private_key = Path(cert_base / "server.pem")

    # Cannot change server name without updating certificates
    host_name = socket.gethostname()
    server_app_uri = f"myselfsignedserver@{host_name}"

    # Add user 1 and user 2 certificate  
    cert_user_manager = CertificateUserManager()
    await cert_user_manager.add_user(Path(cert_base / f"user-certificates/user1-cert.der"), name="user1")
    await cert_user_manager.add_admin(Path(cert_base / f"user-certificates/user2-cert.der"), name="user2")

    server = Server(user_manager=cert_user_manager)

    await server.init()

    await server.set_application_uri(server_app_uri)
    server.set_endpoint("opc.tcp://0.0.0.0:4841/freeopcua/server/")

    # Security policy type
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    #server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_Sign])


    # Load server certificate and private key. This enables endpoints with signing and encryption
    await server.load_certificate(str(server_cert))
    await server.load_private_key(str(server_private_key))

    # Use trust store or not
    if USE_TRUST_STORE:
        trust_store = TrustStore([Path(cert_base / f"server-truststore")], [])
        await trust_store.load()
        validator = CertificateValidator(
            options=CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT,
            trust_store=trust_store,
        )
    else:
        validator = CertificateValidator(
            options=CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_CLIENT
        )
    server.set_certificate_validator(validator)

    idx = 0

    # Populating address space
    myobj = await server.nodes.objects.add_object(idx, "MyObject")
    myvar = await myobj.add_variable(idx, "MyVariable", 0.0)
    await myvar.set_writable()

    async with server:
        while True:
            await asyncio.sleep(1)
            current_val = await myvar.get_value()
            count = current_val + 0.1
            await myvar.write_value(count)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
