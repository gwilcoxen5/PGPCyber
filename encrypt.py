import pgpy

# This will load public key
pubkey, _ = pgpy.PGPKey.from_file('public.asc')

# This is the message that somebody creates to send over, we can make this input prompted also if we want.
message = pgpy.PGPMessage.new("Hello, this is the message!")

# This encrypts message
encrypted_message = pubkey.encrypt(message)

# This saves the encrypted message
with open('message.asc', 'w') as f:
    f.write(str(encrypted_message))
