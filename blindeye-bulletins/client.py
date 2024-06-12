
# &                         BlindEye Bulletin Relay (Server)                           
# %             End-to-end encrypted console socket chat, witten in Python             
# @                               Created by: digu98                                   

# ? (OPTIONAL: For better readability and text highlights, use the Better Comments VS Code extension, or if you want to
# ? map the other characters, save the current setting.json and replace it with the supplied settings.json inside the "Better_Comments" folder)

# % Package Declaration
import socket
from mnemonic import Mnemonic
import bip32utils
import ecdsa
from hashlib import sha256
from colorama import Fore, Back, Style, init
import datetime
from threading import Thread
import random
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# % Colorama init
init(autoreset=True)

# % Choosing random color from specified colors[] array
colors = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX, Fore.MAGENTA, Fore.RED, Fore.WHITE, Fore.YELLOW]
ccolor = random.choice(colors)

# @ Client validation data generator function (this is called every time a new instance is being launched)  
def account_generator():
    #   Mnemonic generation
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    entropy = mnemo.to_entropy(words)

    #   Keypair generation
    key = bip32utils.BIP32Key.fromEntropy(seed)
    key_addr = key.Address()
    public = key.PublicKey().hex()
    private = key.PrivateKey().hex()
    ext_private = key.ExtendedKey()
    ext_pub = key.ExtendedKey(private=False)

    #//address = bip32utils.BIP32Key.fromExtendedKey(ext_pub, public=True).Address()

    #   Signature generation
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private), curve=ecdsa.SECP256k1, hashfunc=sha256)
    verify_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public), curve=ecdsa.SECP256k1, hashfunc=sha256)
    sig = sk.sign(b"e89e7174e6df6e27ea6450201f16b32950278cdb2cd6ba5404f1adfd1ee1db3c1c1fe96c34182f2f579c46c741fe804ab3217bab678655b6a87fed4fcbebf99efd7de938f45ba8e6361c8596b61e51937848181b408603b49a291bbff71e151153d55a5c75c0c8c4a58f5dad6633a1ae67017b0ee2fa8d02c7b2534adf51ea9f")

    #   Storing generated data in array for return
    data = []

    data.append(key_addr)
    data.append(public)
    data.append(sig.hex())

    #   List data
    #//print(f'\tAddress: {key_addr}\n\tPublic: {public}\n\tPrivate: {private}\n\tExtended Private: {ext_private}\n\tMnemonic: {words}')
    #//print(f'\tSignature: {sig.hex()}')
    #//print("\n\n\n")

    return data

# @ Message handler
# ? Data decryption happens here
def message_listener(client_socket, f, server_name):
    while True:
        data = client_socket.recv(10240)
        msg = str(data, "utf-8")
        with open(f"./chats/{server_name}/backup.chat", "a") as fi:
            fi.write(f"{msg}\n")
        
        with open(f"./chats/{server_name}/backup.chat", "r") as fil:
            lines = fil.readlines()
        
        data = f.decrypt(lines[len(lines)-1]) # receive response
        print(f'\n{str(data, "utf-8")}')

# & Main client function
def client_program():
    #   Hostname and port declaration
    host = socket.gethostname()
    port = 5000

    #   Socket creation
    #   Connection to server
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    #   Generate account
    signing_data = account_generator()

    welcome_message = client_socket.recv(10240).decode()
    print(welcome_message)

    channel_list = client_socket.recv(10240).decode()
    print(channel_list)

    specified_address = input("\nPlease specify the bulletin address: ")
    client_socket.send(specified_address.encode())

    # ! The client needs to input the channel's mnemonic key in order to pass the signature check
    specified_key = input("\nPlease specify the mnemonic key for the channel: ")
    
    #   Sending client's public key and signature
    client_socket.send(signing_data[1].encode())
    #//print(f"Public key {signing_data[1]} sent to server\n")
    client_socket.send(signing_data[2].encode())
    #//print(f"Signature {signing_data[2]} sent to server\n")

    # ? Receiving channel's public key, and two signatures
    # % The client will create a verifying key from the server's public key
    server_public_key = client_socket.recv(10240).decode()
    #//print(f"Recieved signature {server_public_key}")
    verify_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(server_public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)

    server_signature = client_socket.recv(10240).decode()
    print(f"Recieved signature {server_signature}")

    server_signature2 = client_socket.recv(10240).decode()
    print(f"Recieved signature {server_signature2}")

    #   Check if either one of the channel's signatures' signed message is the specified key
    # ! If none of the signatures are valid (be the server's or the client's), the client AND the server will force shut down!
    try:
        verify_key.verify(bytes.fromhex(server_signature), bytes(specified_key.encode()))
        print("Server signature verification successful!\n")
    except ecdsa.keys.BadSignatureError:
        print("Server signature verification failure!")
        client_socket.send("Signature verification failure!")
        exit()

    #   Date function
    x = datetime.datetime.now()

    #   Receiving current channel's name
    server_name = client_socket.recv(10240).decode()
    print(f"You are on: {Back.GREEN}{server_name}{Back.RESET}")

    #   Using address as username
    name = signing_data[0]

    # % Specifying the parameters for the PBKDF2HMAC function in order to create an end-to-end encryption
    # = As the string implies, the current salt implementation is insecure
    #   TODO: Better salt implementation
    salt = b"dont_mind_me_i_know_i_am_not_secure"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )

    #   Creating a Fernet key with the kdf variable
    keyy = base64.urlsafe_b64encode(kdf.derive(specified_key.encode()))
    f = Fernet(keyy)

    with open(f"./chats/{server_name}/backup.chat", "r") as file:
        read_lines = file.readlines()

    print("\n".join(read_lines))

    print(f"{Fore.CYAN}// Loaded chat log from disk{Fore.RESET}")

    #   Start a message handler thread
    t = Thread(target=message_listener, args=(client_socket, f, server_name))
    t.daemon = True
    t.start()

    message = f"\n{Fore.YELLOW}// [{x}] {name} has joined the chat{Fore.RESET}"
    message = f.encrypt(bytes(message.encode()))
    client_socket.send(message)

    # % Running code
    while True:
        #   Taking input as message
        message = input("")

        # ? If the message variable is "q", then the process will terminate and the client will disconnect
        #   TODO: Better leave and join message implementation
        if message.lower() == 'q':
            """message = f"{Fore.YELLOW}// [{x}] {name} has left the chat{Fore.RESET}"
            message = f.encrypt(bytes(message.encode()))
            client_socket.send(message)
            message = "".encode()"""
            break
        
        #   Formatting the message for chat readibility and sending it to the Relay (server)
        # * Before sending, the message is encrypted with the earlier created Fernet key
        message = f'[{x}] {ccolor}{name}{Fore.RESET}: {message}'  # show in terminal
        message = f.encrypt(bytes(message.encode()))
        client_socket.send(message)  # send message

    #   Connection closure
    client_socket.close()

# & Main execuing function
if __name__ == '__main__':
    print("Generating information...")
    client_program()