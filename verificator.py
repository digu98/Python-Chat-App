# This is a password-2FA verificator code block
# To be integrated

# Required package import
import hashlib
import pyotp

# data file opener
with open(f"./bulletins/BB-380704888/auth.data", "r") as f:
    fileContent = f.readlines()      
    address = fileContent[0].replace("\n", "")
    saltedPassword = fileContent[1].replace("\n", "")
    TFAkey = fileContent[2].replace("\n", "")
    TFAURL = fileContent[3].replace("\n", "")
    passwordSalt = fileContent[4].replace("\n", "")

# Against 2FA Relay Attack
hashedOTP = ""

# Main Verificator Block
while True:
    
    # Password requester and calculator
    passw = input("Enter password: ")
    calculation = hashlib.sha256(bytes(passw.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest()
    
    # This block checks if the calculated hash from the specified password matches the pre-calculated hash
    if calculation == saltedPassword:
        print("Nice!")
        
        while True:
            totp = pyotp.TOTP(TFAkey)  
            OTPcode = input("Enter the Code : ")
            if totp.verify(OTPcode) is True and hashlib.sha256(bytes(OTPcode.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest() != hashedOTP:
                print("Nice Nice!")
                hashedOTP = hashlib.sha256(bytes(OTPcode.encode("utf-8") + passwordSalt.encode("utf-8"))).hexdigest()
                break
            else:
                # 2FA verification fail block
                print("Nehogy itt akadj már meg...")
                continue
        break
    else:
        # Password verification fail block
        print("Húha baszki")