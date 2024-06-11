# Python Chat App

## Overview
This project is a currently work-in-progress, "proof-of-concept" end-to-end encrypted chat app, written in python

| Written in               | OS                    |
| ------------------------ | --------------------- |
| Work in progress         | Compatible with       |
| [![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)]() | [![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)]() [![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)]() |
| Planned version(s)       | Planned compatibility |
| [![C#](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=C&logoColor=white)]() | [![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)]() [![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)]() |

## How it works
The app uses basic hashed-password authentication and 2FA solutions in order to access a channel (every password an 2FA code is UNIQUE to the channel!).
Because essentially there are no "accounts", each client gets freshly generated RSA keypairs, each time they spin up an instance of `client.py`.
Upon launching `client.py`, making a valid connection to a server and choosing a channel address, it will ask for a channel password (which is never stored in a restoreable format on the server side) and a 2FA code for the channel. After giving it an input, it will recieve a public key and a signature (which has been signed with the server's private key) from the sever.
The client will perform a signature check and if it does not pass the check with the specified key, it kills **the client instance!**
Upon a successful signature verification, the client will in turn, send their own public key and signature for the server to verify. Keep in mind, that upon a signature verification failure, **here, both the client AND the server will shut down!**
If everything succeeds, you will see a message, saying `You are on: <channel name>`. You can now start chatting! The end-to-end encryption uses a salted, passworded (with the given channel password an two salts) Fernet key. The server only relays the encrypted messages to the clients, it does not save the chat into any file, only displays the encrypted messageonto the console (this is currently in only for debugging reasons).

## How to install it
Before running any one of the .py scripts, you have to install some dependencies first!
> Please run `pip install -r requirements.txt` before running any of the files.
In the future, after the project is complete, there will be a compiled and ready product, so no dependencies, or an installed Python instance will be needed.

After you installed the packages:
1. > Please run `bulletin_geneator.py` to generate a bulletin. Please make sure to save the logged password, because the password is only stored in a hashed format, and will NOT be recoverable! This also returns a QR code image, scan this with Google Authenticator to get 2FA codes.
2. > Run `server.py`
3. > Wait for others to connect to the Relay with the `client.py` file

## TO-DO List
Client side:
- [X] Better salt implementation
- [X] Better leave and join message implementation
- [X] File sharing
- [ ] Giving an option between using an already generated account, or using a randomly generated one
- [ ] Completing the encryption system
- [ ] A modern UI design instead of the current console based look, with the py-eel module

Server side:
- [ ] Occasionally writing the member count onto the chat (Possibly could be done client-side)
- [ ] Solving signature error due to other members' messages

Global:
- [ ] C# version of the project

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)