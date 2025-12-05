from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import subprocess, base64

# Get latest commit hash
commit = subprocess.check_output(["git", "log", "-1", "--format=%H"]).strip().decode()

# Load private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Sign commit hash using RSA-PSS SHA256
signature = private_key.sign(
    commit.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_pub = serialization.load_pem_public_key(f.read())

# Encrypt signature using RSA-OAEP SHA256
encrypted_sig = instructor_pub.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Output encrypted signature
print(base64.b64encode(encrypted_sig).decode())
