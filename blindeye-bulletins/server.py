
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
from threading import Thread
import threading
import time
import os

#   Colorama init
init(autoreset=True)

# @ Message handler
def client_listener(cls, client_sockets, address):
    while True:
        try:
            #   Log encrypted message on server console
            #   TODO: Occasionally writing the member count onto the chat (Possibly could be done client-side)
            cls.recv(102400)
            print(f"{Fore.YELLOW}// Relayed message from Bulletin-{Fore.RESET}{Back.LIGHTMAGENTA_EX}{address}")
            #print(str(message, "utf-8"))
            print("\n")
        except ConnectionResetError:
            # print(err)
            client_sockets.remove(cls)
            print(f"// User left from Relay! Current user count for {address}: {len(client_sockets)}")

# & Main server function
def server_program():

    #   Hostname and port declaration
    host = socket.gethostname()
    port = 5000 

    #   Socket creation
    server_socket = socket.socket()
    client_sockets = set()

    #   Bind hostname and port declaration
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))

    #   Max client listeners
    server_socket.listen(5)
    
    # %                 Server validation data                                  
    # =      (for a new channel, please call 'account_generator()',             
    # =      write the results here and edit sig_mnemonic's and sig_private's   
    # =      sign message data with recieved mnemonic key and private key)      
    #
    #
    # @ Address: 
    # & Public: 
    # ! Private: 
    # ! Extended Private: 
    # % Mnemonic: 

    # * Two signatures using mnemonic key and private key as a to-be-signed message
    #   
    # ? Signature: 

    #
    # ? Signature 2: 

    #   TODO: Separate channel generator .py
    #   TODO: Saving generated channel data to a "./channels/" directory > Has been done!
    #   TODO: A channel system, where the client can pick from muliple channels from said "./channels/" directory > Has been done!
    #   TODO: Automating the retrieval of generated channel data

    # % Running code
    while True:
        #   New connection acception, printing said connection and adding connection to set()
        conn, address1 = server_socket.accept()
        print("Connection from: " + str(address1))

        client_sockets.add(conn)

        path = "./bulletins/"
        folderNames = os.listdir(path)

        mess = f"BlindEye Relay v.0.1.0\n\nAvailable channels on {host}:"

        conn.send(mess.encode())
        time.sleep(1)
        conn.send("\n".join(folderNames).encode())
        
        chosen_address = conn.recv(10240).decode()

        with open(f"./bulletins/{chosen_address}/auth.data", "r") as f:
            lines = f.readlines()
            lines = [x.replace("\n", "") for x in lines]

        # % Signing data the server will send to any newcomer client, please change these if you created a new set of credentials
        #
        # ? signing_data[0] = Address
        # ? signing_data[1] = Public key
        # ? signing_data[2] = Signature hash using server's mnemonic key
        # ? signing_data[3] = Signature hash using server's private key

        signing_data = [lines[0], lines[1], lines[6], lines[7]]

        #   Recieve client's public key and siganture
        client_public_key = conn.recv(10240).decode()
        #//print(f"Recieved public key {client_public_key}\n")
        verify_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(client_public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)

        client_signature = conn.recv(10240).decode()
        #//print(f"Recieved signature {client_signature}\n")

        #   Check if the client's supplied signature is valid
        # ! If none of the signatures are valid (be the server's or the client's), the client AND the server will force shut down!
        try:
            verify_key.verify(bytes.fromhex(client_signature), b"e89e7174e6df6e27ea6450201f16b32950278cdb2cd6ba5404f1adfd1ee1db3c1c1fe96c34182f2f579c46c741fe804ab3217bab678655b6a87fed4fcbebf99efd7de938f45ba8e6361c8596b61e51937848181b408603b49a291bbff71e151153d55a5c75c0c8c4a58f5dad6633a1ae67017b0ee2fa8d02c7b2534adf51ea9f")
            print("Client signature verification successful!\n")
        except ecdsa.keys.BadSignatureError:
            print("Client signature verification failure!")
            for soc in client_sockets:
                soc.send("Signature verification failure!".encode())
            break
        
        #   If the verification is successful, 
        #   the server sends it's address, public key and two signatures specified in the "signing_data" array

        conn.send(signing_data[1].encode())
        time.sleep(1)
        #//print(f"Public key {signing_data[1]} sent to client\n")
        
        conn.send(signing_data[2].encode())
        time.sleep(1)
        #//print(f"Signature {signing_data[2]} sent to client\n")
        conn.send(signing_data[3].encode())
        
        time.sleep(1)
        conn.send(signing_data[0].encode())

        #   Start a message handler thread for the newly connected client
        t = Thread(target=client_listener, name=signing_data[0], args=(conn, client_sockets, signing_data[0]))
        t.daemon = True
        t.start()

    # ! If the while True loop is broken, the server will drop any connection and will close itself after it.
    for soc in client_sockets:
        soc.close()

    # ! Main connection closing
    conn.close()

# & Main execuing function
if __name__ == '__main__':
    server_program()