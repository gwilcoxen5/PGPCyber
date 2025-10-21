import pgpy

# prompts user for input on name and email for signature later on
# will be attached to a user id attached to key
name = input("Enter your name: ")
email = input("Enter your email: ")

# sets files for where keys will be saved
priv_filename = "private_key.asc"
pub_filename = "public_key.asc"

# creates the public and private keys
print("Generating RSA key pair!")
key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 2048)

# creates a user id using name and email
uid = pgpy.PGPUID.new(name, email)

# adds user id to key and sets preferences
key.add_uid(
    uid,
    usage=[pgpy.constants.KeyFlags.Sign, pgpy.constants.KeyFlags.EncryptCommunications],
    hashes=[pgpy.constants.HashAlgorithm.SHA256],
    ciphers=[pgpy.constants.SymmetricKeyAlgorithm.AES256],
    compression=[pgpy.constants.CompressionAlgorithm.ZLIB]
)

# saves private key to file
with open(priv_filename, 'w') as f:
    f.write(str(key))

# saves public key to file
with open(pub_filename, 'w') as f:
    f.write(str(key.pubkey))

# if no errors print this
print("\nPGP key pair generated successfully!")
print(f"Private key saved to: {priv_filename}")
print(f"Public key saved to: {pub_filename}")
