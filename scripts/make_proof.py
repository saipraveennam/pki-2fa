# scripts/make_proof.py
import base64, subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# get commit hash
commit_hash = subprocess.check_output(["git", "log", "-1", "--format=%H"]).strip().decode('utf-8')

# load student private key
with open("student_private.pem", "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

# sign commit hash (ASCII)
signature = priv.sign(
    commit_hash.encode('utf-8'),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# load instructor public key & encrypt signature with OAEP-SHA256
with open("instructor_public.pem", "rb") as f:
    from cryptography.hazmat.primitives import serialization as s2
    pub = s2.load_pem_public_key(f.read())

ciphertext = pub.encrypt(
    signature,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print("Commit Hash:", commit_hash)
print("Encrypted Signature (base64):")
print(base64.b64encode(ciphertext).decode('utf-8'))
