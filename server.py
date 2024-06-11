
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
from threading import Thread
import threading
import time
import os
import tqdm
import rsa
from base64 import b64encode, b64decode
import secrets
import hashlib
import pyotp

#   Colorama init
init(autoreset=True)

BUFFER_SIZE = 4096
set_buff_size = 1024

# @ Message handler
def client_listener(cls, client_sockets, address, keylist):
    while True:
        try:
            #   Log encrypted message on server console
            #   TODO: Occasionally writing the member count onto the chat (Possibly could be done client-side)
            message = cls.recv(set_buff_size)
                
            print(f"{Fore.YELLOW}// Relayed message from Bulletin-{Fore.RESET}{Back.LIGHTMAGENTA_EX}{address}")
            #print(str(message, "utf-8"))
            print("\n")
            for cs in client_sockets:
                cs.send(message)
                
        except ConnectionResetError:
            # print(err)
            client_sockets.remove(cls)
            print(f"// User left from Relay! Current user count for {address}: {len(client_sockets)}")
            if len(client_sockets) > 0:
                for cs in client_sockets:
                    cs.send(f"// User left from Relay! Current user count for {address}: {len(client_sockets)}".encode())

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
    # @ Address: 1LTBSSoLjWwB6aVV88vW9wAwAAJDvhWeHU
    # & Public: 03db3b722a3247670b44e0683d885d445454edf3c9b4a487c614fb10dce6d93b75
    # ! Private: 9f99b3dff7fce3c038ca32893578b32aeb22252a4a750c57d74714f3e7b6a162
    # ! Extended Private: xprv9s21ZrQH143K3QeP6zmRfHGNoYF5Z7BgFtmCmvpuk2ZeL3DGgN75MFfBhUzEgCPWc8SdcviSJg3yXrNU5YHfxwDMzWmXeVTTK6sMkpLL2VH
    # % Mnemonic: zoo extra mirror pretty dismiss state misery seed ridge tribe giggle raw friend bird glare possible ladder good flat seek van fox wet rail

    # * Two signatures using mnemonic key and private key as a to-be-signed message
    #   urban grain piece actress yellow slide access champion broken gold blue gold bullet grocery cereal index cabbage attitude toast kingdom yard december adapt foster
    # ? Signature: a42f184e753eef3d860febc9fd077208057311690947f470645dfaa0a63adef617564c850cbd8c07418bc322d52f85364f29c688dca64ca54e37c251d220c5f3

    #   b6f3e384eb329fa7a0c4808e817596648b3b849b77ccfb01a24fcb8a68e864a6
    # ? Signature 2: 90c28fda95c72077724a54316eb874a4bba730a804064eae6a4ddb130eb02f4730466a0a7945d92207460d3cb44484d3e58861a1cefc144e98128da76ece7a95

    #   TODO: Separate channel generator .py
    #   TODO: Saving generated channel data to a "./channels/" directory
    #   TODO: A channel system, where the client can pick from muliple channels from said "./channels/" directory

    # % Running code
    while True:
        #   New connection acception, printing said connection and adding connection to set()
        conn, address1 = server_socket.accept()
        print("Connection from: " + str(address1))

        client_sockets.add(conn)

        path = "./bulletins/"
        folderNames = os.listdir(path)

        mess = f"{host}:"

        conn.send(str(mess + "|||" + "\n".join(folderNames)).encode())
        
        chosen_address = conn.recv(set_buff_size).decode()

        with open(f"./bulletins/{chosen_address}/auth.data", "r") as f:
            lines = f.readlines()
            lines = [x.replace("\n", "") for x in lines]

        # % Signing data the server will send to any newcomer client, please change these if you created a new set of credentials
        #
        # ? signing_data[0] = Address
        # ? signing_data[1] = Hashed and salted password
        # ? signing_data[2] = 2FA Secret key
        # ? signing_data[4] = Secret Salt
        
        with open(f"./bulletins/{chosen_address}/PRIVATE.pem", "r") as f:
            readData = f.read()
            print(readData)
            loadedKey = rsa.PrivateKey.load_pkcs1(readData, "PEM")
            print(loadedKey)

        serverToken = secrets.token_hex(16)
        
        
        
        
        signing_data = [lines[0], lines[1], lines[2], lines[4]]

        #   Recieve client's public key and siganture
        client_public_key = conn.recv(set_buff_size).decode()
        time.sleep(1)
        client_public_key = client_public_key.split("|||")
        #//print(f"Recieved public key {client_public_key}\n")

        time.sleep(1)
        client_signature = conn.recv(set_buff_size).decode()
        #//print(f"Recieved signature {client_signature}\n")

        #   Check if the client's supplied signature is valid
        # ! If none of the signatures are valid (be the server's or the client's), the client AND the server will force shut down!     
        try:
            verify = rsa.verify(client_public_key[1].encode(), b64decode(client_signature), rsa.PublicKey.load_pkcs1(client_public_key[0], "PEM"))
        except rsa.pkcs1.VerificationError:
            print("Verify failed")
            for soc in client_sockets:
                    soc.send("Signature verification failure!".encode())
            break
        
        print("Signature verification successful!")
        
        #   If the verification is successful, 
        #   the server sends it's address, public key and two signatures specified in the "signing_data" array
        
        with open(f"./bulletins/{chosen_address}/PRIVATE.pem", "r") as f:
            readDataPrivate = f.read()
            loadedPrivateKey = rsa.PrivateKey.load_pkcs1(readDataPrivate, "PEM")
        
        with open(f"./bulletins/{chosen_address}/PUBLIC.pem", "r") as f:
            readDataPublic = f.read()
            loadedPublicKey = rsa.PublicKey.load_pkcs1(readDataPublic, "PEM")

        server_signature = b64encode(rsa.sign(serverToken.encode("utf-8"), loadedPrivateKey, "SHA-512"))
        print(verify)
        
        conn.send(str(readDataPublic + "|||" + serverToken).encode())
        time.sleep(1)
        #//print(f"Public key {signing_data[1]} sent to client\n")
        
        conn.send(server_signature)
        time.sleep(1)
        #//print(f"Signature {signing_data[2]} sent to client\n")
        
        time.sleep(1)
        password_2fa = conn.recv(set_buff_size).decode()
        password_2fa = password_2fa.split("|||")
        
        
        
        # File opener
        with open(f"./bulletins/{chosen_address}/auth.data", "r") as f:
            fileContent = f.readlines()      
            saltedPassword = fileContent[1].replace("\n", "")
            TFAkey = fileContent[2].replace("\n", "")
            passwordSalt = fileContent[4].replace("\n", "")

        # Against 2FA Relay Attack
        hashedOTP = ""

        # Main Verificator Block
        # Password requester and calculator
        passw = password_2fa[0]
        calculation = hashlib.sha256(bytes(passw.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest()
            
        # This block checks if the calculated hash from the specified password matches the pre-calculated hash
        if calculation == saltedPassword:
            print("Nice!")
                
            totp = pyotp.TOTP(TFAkey)  
            OTPcode = password_2fa[1]
            if totp.verify(OTPcode) is True and hashlib.sha256(bytes(OTPcode.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest() != hashedOTP:
                print("Authentication Successful!")
                hashedOTP = hashlib.sha256(bytes(OTPcode.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest()
                conn.send("CODE_SUCCESS".encode())
            else:
                # 2FA verification fail block
                print("Authentication Failed: 2FA Fail")
                conn.send("CODE_2FA_FAIL".encode())
        else:
            # Password verification fail block
            print("Authentication Failed: Password Fail")
            conn.send("CODE_PASSWORD_FAIL".encode())
        
        conn.send(signing_data[0].encode())
        
        # Write specific client public key to file
        with open(f"./bulletins/{chosen_address}/userkeys/{client_public_key[1]}.pem", "w") as f:
            f.write(client_public_key[0])
            
        FernetPasswordSalt = secrets.token_hex(128)
        FernetPasswordSalt2 = secrets.token_hex(128)
        
        time.sleep(0.2)

        path = f"./bulletins/{chosen_address}/userkeys/"
        fileNames = os.listdir(path)
        
        listOfkeys = []
        
        for files in fileNames:
            with open(f"./bulletins/{chosen_address}/userkeys/{files}", "r") as f:
                gotPubKey = f.read()
            
            listOfkeys.append(gotPubKey)
        
        print(listOfkeys)
        
        conn.send(str(len(listOfkeys)).encode())
        time.sleep(0.1)
        for conns in client_sockets:
            for kys in listOfkeys:
                conns.send(kys.encode())
                time.sleep(0.1)
        
        time.sleep(0.1)
        
        # Fernet Password Salt Sending
        message = b64encode(rsa.encrypt(FernetPasswordSalt.encode("utf-8"), rsa.PublicKey.load_pkcs1(client_public_key, "PEM")))
        message2 = b64encode(rsa.encrypt(FernetPasswordSalt2.encode("utf-8"), rsa.PublicKey.load_pkcs1(client_public_key, "PEM")))
        conn.send(message)
        time.sleep(0.1)
        conn.send(message2)
        
        # listOfkeys = []
        
        #   Start a message handler thread for the newly connected client
        t = Thread(target=client_listener, name=signing_data[0], args=(conn, client_sockets, signing_data[0], listOfkeys))
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