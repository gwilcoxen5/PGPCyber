import pgpy
import time
import warnings
warnings.filterwarnings("ignore")


#list of key sizes we chose to test, this is in bits
key_sizes = [1024, 2048, 4096]

# fake message to use for testing like before
message = "A" * (1024 * 1024)

# number of times to run each test
runs = 3

# runs sveral times and returns the average time it was
def time_it(fn, runs=runs):
    times = []
    for _ in range(runs):
        start_time = time.perf_counter()
        fn()
        end_time = time.perf_counter()
        times.append(end_time - start_time)

        # calculates time in milliseconds
    return sum(times) / len(times) * 1000.0

def main():
    print("key_bits,keygen_ms,encrypt_ms,decrypt_ms,sign_ms,verify_ms")

    # test each key size
    for bits in key_sizes:
        
        # time how long it takes to gen the key
        def gen_key():
            pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, bits)

        time_keygen = time_it(gen_key)

        # creates key for testing e/s
        key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, bits)
        uid = pgpy.PGPUID.new("Test User", email="test@gmail.com")

        # add user id, allows e/s
        key.add_uid(uid, usage={pgpy.constants.KeyFlags.Sign, pgpy.constants.KeyFlags.EncryptCommunications})

        # unlocks private key, empty again
        key.unlock("")

        pub = key.pubkey
        msg = pgpy.PGPMessage.new(message)
        data = message.encode("utf-8")

        # encrypt
        time_encryption = time_it(lambda: pub.encrypt(msg))

        enc = pub.encrypt(msg)

        # decrypt
        time_decryption = time_it(lambda: key.decrypt(enc))

        # sign
        time_sign = time_it(lambda: key.sign(data))

        sig = key.sign(data)

        # verify
        time_verify = time_it(lambda: pub.verify(data, sig))

        # shows results for the key size
        print(f"{bits},{time_keygen:.1f},{time_encryption:.1f},{time_decryption:.1f},{time_sign:.1f},{time_verify:.1f}")

# run program
if __name__ == "__main__":
    main()
