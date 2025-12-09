import pgpy
import time
import warnings
warnings.filterwarnings("ignore")


# how many times each operation will repeat to get an average of them
number_times = 5

# message sizes we want to test, these are in bytes
# 1 KB, 10 KB, 100 KB, 500 KB, 1 MB, 5 MB
message_sizes = [
    1 * 1024,
    10 * 1024,
    100 * 1024,
    500 * 1024,
    1 * 1024 * 1024,
    5 * 1024 * 1024,
]

# loads the public and private keys that were generated before

def load_keys():
    pubkey, _ = pgpy.PGPKey.from_file("public_key.asc")
    privkey, _ = pgpy.PGPKey.from_file("private_key.asc")

    # the key I have set up uses an empty passphrase so I unlock it here
    privkey.unlock("")
    return pubkey, privkey

# creates fake message of size_bytes chracters for testing

def make_message(size_bytes: int) -> str:
    return "A" * size_bytes

# for a specific message size this will create a fake message, encrypt it and time the time for that
# decrypt it and time the time for that, sign the mesage and time the time for that, verify the signature
# and time the time for that, as well as measure how big the encrypted message and signature are

def benchmark_for_size(pubkey, privkey, size_bytes: int):
    enc_times = [] # store e times
    dec_times = [] # stores d times
    sign_times = [] # stores s times
    verify_times = [] # stores v times

    cipher_size_bytes = None # will store e size
    sig_size_bytes = None # will store s size

# thsi runs each operation number_times times, to find average

    for _ in range(number_times):
        # create a message
        plaintext = make_message(size_bytes)

        # encrypt
        msg = pgpy.PGPMessage.new(plaintext)

        start_time = time.perf_counter()
        encrypted = pubkey.encrypt(msg)
        end_time = time.perf_counter()
        enc_times.append(end_time - start_time) # how long e took

        # saves size of ciphertext
        cipher_str = str(encrypted)
        cipher_bytes = cipher_str.encode("utf-8")
        if cipher_size_bytes is None:
            cipher_size_bytes = len(cipher_bytes)

        # decrypt
        start_decrypt_time = time.perf_counter()
        decrypted = privkey.decrypt(encrypted)
        end_decrypt_time = time.perf_counter()
        dec_times.append(end_decrypt_time - start_decrypt_time) # how long d took

        if decrypted.message != plaintext:
            print("WARNING: decrypted message did not match plaintext!")

        # sign
        data_bytes = plaintext.encode("utf-8")

        start_sign_time = time.perf_counter()
        signature = privkey.sign(data_bytes)
        end_sign_time = time.perf_counter()
        sign_times.append(end_sign_time - start_sign_time) # how long s took

        # saves size of signature
        sig_str = str(signature)
        sig_bytes = sig_str.encode("utf-8")
        if sig_size_bytes is None:
            sig_size_bytes = len(sig_bytes)

        # verify
        start_verify_time = time.perf_counter()
        vr = pubkey.verify(data_bytes, signature)
        end_verify_time = time.perf_counter()
        verify_times.append(end_verify_time - start_verify_time) # how long verify took

        if not vr:
            print("WARNING: verification failed for size", size_bytes)

    # calculates average time in milliseconds
    def avg_ms(times):
        return (sum(times) / len(times)) * 1000.0

    # returns all results for message size
    result = {
        "plaintext_size_bytes": size_bytes,
        "ciphertext_size_bytes": cipher_size_bytes,
        "signature_size_bytes": sig_size_bytes,
        "encrypt_time_ms": avg_ms(enc_times),
        "decrypt_time_ms": avg_ms(dec_times),
        "sign_time_ms": avg_ms(sign_times),
        "verify_time_ms": avg_ms(verify_times),
    }
    return result

# loads keys before testing
def main():
    pubkey, privkey = load_keys()

    print("plaintext_bytes,ciphertext_bytes,signature_bytes,encrypt_ms,decrypt_ms,sign_ms,verify_ms")

    for size in message_sizes:
        res = benchmark_for_size(pubkey, privkey, size)
        print(
            f"{res['plaintext_size_bytes']},"
            f"{res['ciphertext_size_bytes']},"
            f"{res['signature_size_bytes']},"
            f"{res['encrypt_time_ms']:.3f},"
            f"{res['decrypt_time_ms']:.3f},"
            f"{res['sign_time_ms']:.3f},"
            f"{res['verify_time_ms']:.3f}"
        )

# run program
if __name__ == "__main__":
    main()
