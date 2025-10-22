import pgpy

# This loads private key
privkey, _ = pgpy.PGPKey.from_file('private_key.asc')
privkey.unlock("")  
# This doesn't have password protection but we can add this later if we want
# We just have to set for password protection and this will be what is used to unlock (figure this out later, working on this)

# Load encrypted message
message = pgpy.PGPMessage.from_file('message.asc')

# This decrypts message
decrypted = privkey.decrypt(message)
print("Decrypted message:", decrypted.message)
