import base64, subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

commit_hash = subprocess.check_output(["git", "log", "-1", "--format=%H"]).strip().decode('utf-8')

with open("student_private.pem", "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

signature = priv.sign(
    commit_hash.encode('utf-8'),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

with open("student_public.pem", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())

print("Commit Hash:", commit_hash)
print("Signature (base64):")
print(base64.b64encode(signature).decode('utf-8'))
