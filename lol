
    # @ Bulletin board authentication data generator
# * (should be called for separate channel creation)
def bulletin_board_generator():
    #   Bulletin Mnemonic generation (Channel access code)
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    entropy = mnemo.to_entropy(words)

    #   Bulletin Keypair generation
    key = bip32utils.BIP32Key.fromEntropy(seed)
    key_addr = key.Address()
    public = key.PublicKey().hex()
    private = key.PrivateKey().hex()
    ext_private = key.ExtendedKey()
    ext_public = key.ExtendedKey(private=False)

    #   Bulletin Signature generation
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private), curve=ecdsa.SECP256k1, hashfunc=sha256)
    sk2 = ecdsa.SigningKey.from_string(bytes.fromhex(private), curve=ecdsa.SECP256k1, hashfunc=sha256)
    verify_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public), curve=ecdsa.SECP256k1, hashfunc=sha256)
    sig_mnemonic = sk.sign(bytes(words.encode()))
    sig_private = sk2.sign(bytes(private.encode()))

    #   List data
    print(f'\tAddress: {key_addr}\n\tPublic: {public}\n\tPrivate: {private}\n\tExtended Private: {ext_private}\n\tMnemonic: {words}')
    print(f'\tSignature: {sig_mnemonic.hex()}\n\tSignature 2: {sig_private.hex()}')
    print("\n\n\n")

    path = "./bulletins/"
    
    path_final = os.path.join(path, str(key_addr))
    os.makedirs(path_final)

    with open(f"./bulletins/{key_addr}/auth.data", "w") as f:
        f.write(f"{key_addr}\n")
        f.write(f"{public}\n")
        f.write(f"{ext_public}\n")
        f.write(f"{private}\n")
        f.write(f"{ext_private}\n")
        f.write(f"{words}\n")
        f.write(f"{sig_mnemonic.hex()}\n")
        f.write(f"{sig_private.hex()}\n")
        f.write(f"{os.urandom(128).hex()}\n")

# & Main execuing function
if __name__ == '__main__':
    bulletin_board_generator()