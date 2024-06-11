
# &                         BlindEye Bulletin Generator                                
# %             End-to-end encrypted console socket chat, witten in Python             
# @                               Created by: digu98                                   

# ? (OPTIONAL: For better readability and text highlights, use the Better Comments VS Code extension, or if you want to
# ? map the other characters, save the current setting.json and replace it with the supplied settings.json inside the "Better_Comments" folder)


# % Package Declaration
from hashlib import sha256, sha512
from colorama import Fore, Back, Style, init
import os
import time 
import pyotp 
import qrcode 
import secrets
import textwrap
import string
import rsa
from base64 import b64encode, b64decode

def bulletin_board_generator():
    #2FA Key Generation Declaration
    secret_key = pyotp.random_base32()
    
    salt = secrets.token_bytes(128).hex()

    chatName = input("Please enter the chat name (leave it empty to get a random name): ")
    
    bulletinNumber = ""
    FolderSafe = ""

    if chatName.strip() == "":
        bulletinNumber = textwrap.wrap(str(secrets.randbelow(999999999)), 3)
        chatNewName = f"BB-{bulletinNumber[0]}:{bulletinNumber[1]}:{bulletinNumber[2]}"
        FolderSafe = f"BB-{bulletinNumber[0]}{bulletinNumber[1]}{bulletinNumber[2]}"
        
        #2FA auth URL generation and display
        totp_auth = pyotp.totp.TOTP( 
        secret_key).provisioning_uri( 
        name=chatNewName, 
        issuer_name='Bulletins') 
        
        #print(totp_auth)

        #2FA auth URL to QR code conversion
        qrcode.make(totp_auth).save(f"qr_auth_{bulletinNumber[0]}{bulletinNumber[1]}{bulletinNumber[2]}.png") 
        
    else:
        bulletinNumber = textwrap.wrap(str(secrets.randbelow(999999999)), 3)
        chatNewName = f"BB-{chatName}::{bulletinNumber[0]}:{bulletinNumber[1]}:{bulletinNumber[2]}"
        FolderSafe = f"BB-{chatName}{bulletinNumber[0]}{bulletinNumber[1]}{bulletinNumber[2]}"
        
        #2FA auth URL generation and display
        totp_auth = pyotp.totp.TOTP( 
        secret_key).provisioning_uri( 
        name=chatName, 
        issuer_name='Bulletins') 
        
        #print(totp_auth)

        #2FA auth URL to QR code conversion
        qrcode.make(totp_auth).save(f"qr_auth_{chatName}_{bulletinNumber[0]}{bulletinNumber[1]}{bulletinNumber[2]}.png") 


    charlist = string.ascii_letters + string.digits + string.punctuation
    bulletin_password = ""

    for _ in range(16):
        bulletin_password += str(''.join(secrets.choice(charlist)))
        
    #print(bulletin_password)


    # List data
    print("\n")
    print(f'\tAddress name: {chatName}\n\tFinal Address: {chatNewName}\n\tBulletin Password: {bulletin_password} - NOTE! Please write down the password, as it will NOT be saved in a recoverable format!\n\t2FA Secret Key: {secret_key}\n\t2FA Auth URL: {totp_auth}')
    print("\n\n\n")

    path = "./bulletins/"
        
    path_final = os.path.join(path, str(FolderSafe))
    
    os.makedirs(path_final)
    os.makedirs(f"./bulletins/{FolderSafe}/userkeys")

    saltedHashedPassword = sha256(bytes(bulletin_password.encode("utf-8") + salt.encode("utf-8"))).hexdigest()
    
    keysize = 2048
    (public, private) = rsa.newkeys(keysize)
    
    msg1 = secrets.token_hex(16)
    msgFalse = sha512(bytes(str(secrets.token_hex(16)).encode("utf-8"))).hexdigest()
    
    encrypted = b64encode(rsa.encrypt(msg1.encode("utf-8"), public))
    decrypted = rsa.decrypt(b64decode(encrypted), private)
    signature = b64encode(rsa.sign(msg1.encode("utf-8"), private, "SHA-512"))
    verify = rsa.verify(msg1.encode("utf-8"), b64decode(signature), public)
    
    """
    try:
        verify2 = rsa.verify(msgFalse.encode("utf-8"), b64decode(signature), public)
    except rsa.pkcs1.VerificationError:
        return print("Verify failed")
    """
    
    """
    print(str(private.save_pkcs1("PEM").decode("utf-8")))
    print(str(public.save_pkcs1("PEM").decode("utf-8")))
    print(msg1)
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Signature: {signature}")
    print(f"Verify: {verify}")
    # print(f"Verify 2: {verify2}")
    # rsa.verify(msg2, b64decode(signature), public)
    """
    
    with open(f"./bulletins/{FolderSafe}/auth.data", "w") as f:
        f.write(f"{chatName}\n")
        f.write(f"{saltedHashedPassword}\n")
        f.write(f"{secret_key}\n")
        f.write(f"{totp_auth}\n")
        f.write(f"{salt}\n")
    
    with open(f"./bulletins/{FolderSafe}/PRIVATE.pem", "wb") as f:
        f.write(private.save_pkcs1("PEM"))
    
    with open(f"./bulletins/{FolderSafe}/PUBLIC.pem", "wb") as f:
        f.write(public.save_pkcs1("PEM"))
    
# & Main execuing function
if __name__ == '__main__':
    bulletin_board_generator()