import pgpy
import warnings
warnings.filterwarnings("ignore")

public_key_path = 'public_key.asc' # used to verify sig
message_path = 'plaintext.txt'
signature_path = 'signature.asc'

def main():

    # load pub key
    pubkey, _ = pgpy.PGPKey.from_file(public_key_path)

    # read message as rb so any type of file will work, load message and sig
    data = open(message_path, 'rb').read()
    sig = pgpy.PGPSignature.from_file(signature_path)

    # verify sig, print VAL/INVAL, or error
    try:
        vr = pubkey.verify(data, sig)  # verify w/ public key
        if vr:
            print('Signature is VALID for message.asc with this public key.')
        else:
            print('Signature is INVALID for message.asc with this public key.')
    except Exception as e:
        print('Verification failed with an exception:')
        print(e)

# run program
if __name__ == '__main__':
    main()