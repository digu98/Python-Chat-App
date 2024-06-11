
# &                         BlindEye Bulletin Relay (Server)                           
# %             End-to-end encrypted console socket chat, witten in Python             
# @                               Created by: digu98                                   

# ? (OPTIONAL: For better readability and text highlights, use the Better Comments VS Code extension, or if you want to
# ? map the other characters, save the current setting.json and replace it with the supplied settings.json inside the "Better_Comments" folder)

# % Package Declaration
import socket
from mnemonic import Mnemonic
from hashlib import sha256
from colorama import Fore, Back, Style, init
import datetime
from threading import Thread
import random
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat import backends
import os
from treelib import Node, Tree
import tqdm
import rsa
import secrets
from base64 import b64encode, b64decode
import time

# % Colorama init
init(autoreset=True)

set_buff_size = 1024

BUFFER_SIZE = 4096

# % Choosing random color from specified colors[] array
colors = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLACK_EX, Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX, Fore.MAGENTA, Fore.RED, Fore.WHITE, Fore.YELLOW]
ccolor = random.choice(colors)

# @ Client validation data generator function (this is called every time a new instance is being launched)  
def account_generator():
    
    # RSA Keypair Generator
    keysize = 4096
    (public, private) = rsa.newkeys(keysize)
    
    # Random Username
    clientToken = secrets.token_hex(16)
    
    # encrypted = b64encode(rsa.encrypt(clientToken.encode("utf-8"), public))
    # decrypted = rsa.decrypt(b64decode(encrypted), private)
    # signature = b64encode(rsa.sign(clientToken.encode("utf-8"), private, "SHA-512"))
    # verify = rsa.verify(clientToken.encode("utf-8"), b64decode(signature), public)

    #   Keypair specification
    key_addr = clientToken

    #   Signature generation
    signature = b64encode(rsa.sign(clientToken.encode("utf-8"), private, "SHA-512"))

    #   Storing generated data in array for return
    data = []
    
    public = public.save_pkcs1("PEM").decode("utf-8")
    private = private.save_pkcs1("PEM").decode("utf-8")

    data.append(key_addr)
    data.append(public)
    data.append(signature)
    data.append(private)

    return data

# @ Message handler
# ? Data decryption happens here
def message_listener(client_socket, server_name, privateKey):
    while True:
        data = client_socket.recv(set_buff_size).decode()
        time.sleep(0.1)
        keyListLen = client_socket.recv(set_buff_size).decode()
        listKey = []
        time.sleep(0.1)
        for _ in range(int(keyListLen)):
            current_key = client_socket.recv(set_buff_size).decode()
            listKey.append(current_key)
            time.sleep(0.1)
            
        print(listKey)
        
        with open(f"./chats/{server_name}/keyList.pem", "w") as fi:
            for curKey in listKey:
                fi.write(f"{curKey}\n")
        
        with open(f"./chats/{server_name}/backup.chat", "a") as fi:
            fi.write(f"{data}\n")
        
        splitMsg = data.split("|||")
        
        for encMessage in splitMsg:
            try:
                print(encMessage)
                message = rsa.decrypt(b64decode(encMessage), rsa.PrivateKey.load_pkcs1(privateKey, "PEM"))
            except rsa.DecryptionError:
                print("This message is not encrypted with my key...")
            else:
                print("Message encrypted with my public key!")
        
        data = message # receive response
        
        if data == "fileSend":
            received = client_socket.recv(BUFFER_SIZE).decode()
            filename, filesize, username = received.split("|")
            # remove absolute path if there is
            filename = os.path.basename(filename)
            # convert to integer
            filesize = int(filesize)

            progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(f"./chats/{server_name}/files/{filename}", "wb") as f:
                while True:
                    # read 1024 bytes from the socket (receive)
                    bytes_read = client_socket.recv(BUFFER_SIZE)
                    if not bytes_read:    
                        # nothing is received
                        # file transmitting is done
                        break
                    # write to the file the bytes we just received
                    f.write(bytes_read)
                    # update the progress bar
                    progress.update(len(bytes_read))
            print(f"{username} => {Fore.MAGENTA}[{filename} - {int(filesize)/1000} kb]{Fore.RESET}")

        print(f'\n{str(data, "utf-8")}')

# & Main client function
def client_program():
    #   Hostname and port declaration
    host = socket.gethostname()
    port = 5000

    #   Socket creation
    #   Connection to server
    client_socket = socket.socket()
    client_socket.connect((host, port))

    #   Generate account
    signing_data = account_generator()

    host = client_socket.recv(set_buff_size).decode()
    host = host.split("|||")
    channel_list = host[1]
    host = host[0]
    welcome_message = f"BlindEye Relay v.0.1.0\n\nAvailable channels on {host}"
    print(welcome_message)
    
    tree = Tree()

    tree.create_node(host, host)

    clist = channel_list.split("\n")

    for c, v in enumerate(clist):
        tree.create_node(v, c, parent=host)

    print(tree.show(stdout=False))
    
    #time.sleep(1)
    #clist = channel_list.split("\n")
    #for c, v in enumerate(clist):
    #    print(c)
    
    specified_address = input("\nPlease specify the bulletin address: ")
    client_socket.send(specified_address.encode())

    # ! The client needs to input the channel's password in order to pass the signature check
    specified_key = input("\nPlease specify the password for the channel: ")
    
    # ! The client needs to input the channel's 2FA code in order to pass the signature check
    specified_2fa = input("\nPlease specify the 2FA code for the channel: ")
    
    #   Sending client's public key and signature
    client_socket.send(str(signing_data[1] + "|||" + signing_data[0]).encode())
    #//print(f"Public key {signing_data[1]} sent to server\n")
    client_socket.send(signing_data[2])
    #//print(f"Signature {signing_data[2]} sent to server\n")
    time.sleep(1)
    # ? Receiving channel's public key, and two signatures
    # % The client will create a verifying key from the server's public key
    server_public_key = client_socket.recv(set_buff_size).decode()
    server_public_key = server_public_key.split('|||')
    #//print(f"Recieved signature {server_public_key}")
    time.sleep(1)
    server_signature = client_socket.recv(set_buff_size).decode()
    print(f"Recieved signature {server_signature}")

    #   Check if either one of the channel's signatures signed message is the specified key
    # ! If none of the signatures are valid (be the server's or the client's), the client AND the server will force shut down!
    try:
        verify = rsa.verify(server_public_key[1].encode(), b64decode(server_signature), rsa.PublicKey.load_pkcs1(server_public_key[0], "PEM"))
    except rsa.pkcs1.VerificationError:
        print("Server signature verification failure!")
        client_socket.send("Signature verification failure!".encode())
        exit()
    
    print("Server signature verification successful!\n")
    
    # Password and 2FA code sending for checking
    client_socket.send(str(specified_key + "|||" + specified_2fa).encode())
    
    server_access_code = client_socket.recv(set_buff_size).decode()
    
    if server_access_code == "CODE_SUCCESS":
        print("Successful login!")
    elif server_access_code == "CODE_2FA_FAIL":
        print("Login fail by 2FA Code!")
        time.sleep(1)
        exit()
    elif server_access_code == "CODE_PASSWORD_FAIL":
        print("Login fail by Password!")
        time.sleep(1)
        exit()
    else:
        print("Unforeseen error! Sorry!")
        time.sleep(1)
        exit()
    
    #   Date function
    x = datetime.datetime.now()

    #   Receiving current channel's name
    server_name = client_socket.recv(set_buff_size).decode()
    print(f"You are on: {Back.GREEN}{server_name}{Back.RESET}")
    
    server_name = server_name.replace(":", "")
    
    time.sleep(0.1)
    
    
    keyListLen = client_socket.recv(set_buff_size).decode()
    keyList = []
    time.sleep(0.1)
    for _ in range(int(keyListLen)):
        current_key = client_socket.recv(set_buff_size).decode()
        keyList.append(current_key)
        time.sleep(0.1)
        
    time.sleep(0.1)
    FernetSalt = client_socket.recv(set_buff_size).decode("utf-8")
    time.sleep(0.1)
    FernetSalt2 = client_socket.recv(set_buff_size).decode("utf-8")
    
    for _ in keyList:
        try:
            FernetSalt = rsa.decrypt(b64decode(FernetSalt), rsa.PrivateKey.load_pkcs1(signing_data[3], "PEM"))
        except rsa.DecryptionError:
            print("[1] This message is not encrypted with my key...")
        else:
            print("[1] Message encrypted with my public key!")

        try:
            FernetSalt2 = rsa.decrypt(b64decode(FernetSalt2), rsa.PrivateKey.load_pkcs1(signing_data[3], "PEM"))
        except rsa.DecryptionError:
            print("[1] This message is not encrypted with my key...")
        else:
            print("[1] Message encrypted with my public key!")
        
    path = "./chats/"
    
    path_final = os.path.join(path, str(server_name))
    try:
        os.makedirs(path_final)
    except FileExistsError:
        pass

    #   Using address as username
    name = signing_data[0]

    # % Specifying the parameters for the PBKDF2HMAC function in order to create an end-to-end encryption
    # = As the string implies, the current salt implementation is insecure
    #   TODO: Better salt implementation
    salt = b"dont_mind_me_i_know_i_am_not_secure"
    
    # Fernet on hold until improved, current implementation: RSA keys -> [Might keep current implementation]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FernetSalt,
        iterations=390000,
        backend=backends.default_backend()
    )

    #   Creating a Fernet key with the kdf variable
    keyy = base64.urlsafe_b64encode(kdf.derive(str(f"{specified_key}{server_name}{FernetSalt2}").encode()))
    f = Fernet(keyy)
    
    try:
        with open(f"./chats/{server_name}/backup.chat", "r") as file:
            read_lines = file.readlines()
            
            for i in read_lines:
                message = f.decrypt(i)
                i = i.encode()
                print("".join(str(message, "utf-8")))
                
    except FileNotFoundError:
        with open(f"./chats/{server_name}/backup.chat", "w") as file:
            file.write("\n")

    print(f"{Fore.CYAN}// Loaded chat log from disk{Fore.RESET}")

    #   Start a message handler thread
    t = Thread(target=message_listener, args=(client_socket, server_name, signing_data[3]))
    t.daemon = True
    t.start()

    message = f"{Fore.YELLOW}// [{x}] {name} has joined the chat{Fore.RESET}".encode('utf-8')
    
    message = f.encrypt(bytes(message.encode()))
    client_socket.send(message)
    time.sleep(0.1)
    
    with open(f"./chats/{server_name}/backup.chat", "a") as fi:
        fi.write(f"{message}")

    # % Running code
    while True:
        #   Taking input as message
        message = input("")
        
        msgList = []
        
        with open(f"./chats/{server_name}/keyList.pem", "r") as fi:
            listKey = fi.read()
            listKey = listKey.split("\n")
            for curKey in listKey:
                msgList.append(curKey)

        # ? If the message variable is "q", then the process will terminate and the client will disconnect
        #   TODO: Better leave and join message implementation
        if message.lower() == 'q':
            message = f"{Fore.YELLOW}// [{x}] {name} has left the chat{Fore.RESET}"
            
            client_socket.send(str(len(keyList)).encode())
            time.sleep(0.1)
            for uKey in keyList:
                message = b64encode(rsa.encrypt(message.encode("utf-8"), rsa.PublicKey.load_pkcs1(uKey, "PEM")))
                client_socket.send(message)
                time.sleep(0.1)
            
            break
        
        if message.lower() == 'fileNOTWORKING!':
            to_send_filepath = input("Please specify the file to be sent: ")
            BUFFER_SIZE = 4096

            client_socket.send(b"fileSend")

            filesize = os.path.getsize(to_send_filepath)

            client_socket.send(f"{to_send_filepath}|{filesize}|{name}".encode())

            progress = tqdm.tqdm(range(filesize), f"Sending {to_send_filepath}...", unit="B", unit_scale=True, unit_divisor=1024)

            with open(to_send_filepath, "rb") as f:
                while True:
                    # read the bytes from the file
                    bytes_read = f.read(BUFFER_SIZE)
                    if not bytes_read:
                        # file transmitting is done
                        break
                    # we use sendall to assure transimission in 
                    # busy networks
                    client_socket.sendall(bytes_read)
                    # update the progress bar
                    progress.update(len(bytes_read))
        else:
            #   Formatting the message for chat readibility and sending it to the Relay (server)
            # * Before sending, the message is encrypted with the earlier created Fernet key
            
            message = f'[{x}] {ccolor}{name}{Fore.RESET}: {message}'  # show in terminal
            
            message = f.encrypt(bytes(message.encode()))
            client_socket.send(message)  # send message
            
    #   Connection closure
    client_socket.close()
    
    exit()

# & Main execuing function
if __name__ == '__main__':
    print("Generating information...")
    client_program()