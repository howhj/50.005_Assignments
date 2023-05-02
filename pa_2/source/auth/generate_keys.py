from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import sys

if len(sys.argv) == 1:
    suffix = ""
else:
    suffix = sys.argv[1]

# Generate our key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
)

# Write our private key to disk for safe keeping
with open(suffix + "_private_key.pem", "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Generate a CSR
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name(
            [
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, "Singapore"
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Singapore"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SUTD"),
                x509.NameAttribute(NameOID.COMMON_NAME, "sutd.edu.sg"),
            ]
        )
        # Sign the CSR with our private key.
    )
    .sign(key, hashes.SHA256())
)

# Write our CSR out to disk.
with open(suffix + "_certificate_request.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
