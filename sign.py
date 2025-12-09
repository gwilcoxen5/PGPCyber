import pgpy
import warnings
warnings.filterwarnings("ignore")


private_key_path = 'private_key.asc' # loc of priv key
message_path = 'plaintext.txt'
signature_path = 'signature.asc' # where to save signature

def main():
    # load private key
    privkey, _ = pgpy.PGPKey.from_file(private_key_path)
    try:
        privkey.unlock("")  # empty passphrase
    except Exception as e:
        print(f"Warning: could not unlock private key with empty passphrase: {e}")

    # read file as rb, this way it works with any type of file
    data = open(message_path, 'rb').read()
    
    # creates digital sig so it proves that it got signed
    sig = privkey.sign(data)

    # save sig
    with open(signature_path, 'w') as f:
        f.write(str(sig))

    # prints message for if it works
    print('Message signed successfully.')
    print(f'Signature saved to: {signature_path}')
    print(f'Signed over file bytes of: {message_path}')

# run program
if __name__ == '__main__':
    main()
