# BlindEye (Bulletin Boards)

## Overview
BlindEye is a work in progress, proof of concept, end-to-end encrypted console socket chat.
This is only for showing that an application like this CAN be done, but nenessarily should be made, as better languages for tasks like this exist and I cannot fully guarantee the security of the currently implemented encryptions, as this software uses multiple dependencies.

| Written in               | OS                    |
| ------------------------ | --------------------- |
| Work in progress         | Compatible with       |
| [![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)]() | [![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)]() [![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)]() |

## How it works
BlindEye uses BIP32 keys derived from BIP39 mnemonic keys[^1] for account and server verification.
Each client gets freshly generated account details, each time they spin up an instance of `client.py`.
Upon launching `client.py`, it will ask for a **mnemonic key.** After giving it an input, it will recieve a public key and a signature (which has been signed with the server's private key) from the sever.
The client will perform a signature check and if it does not pass the check with the specified key, it kills **both the client AND the server!**
Upon a successful signature verification, the client will in turn, send their own public key and signature for the server to verify. Keep in mind, that upon a signature verification failure, **here as well, both the client AND the server will shut down!**
If everything succeeds, you will see a message, saying `You are on: <channel name>`. You can now start chatting! The end-to-end encryption uses a salted, passworded (with the given mnemonic key) Fernet key. The server only relays the encrypted messages to the clients, it does not save the chat into any file, only displays the encrypted messageonto the console.

[^1]: Because of these standards, this essentially also creates usable Bitcoin wallet data, though there is no functionality coded into the app which would benefit from this. This is only an intermediary measure until a better authentication solution is implemented. Needless to say, ***DO NOT use any these for actual fund storage, because of the reasons mentioned above!***

## How to install it
Before running any one of the .py scripts, you have to install some dependencies first!
> Please run `pip install -r requirements.txt` before running any of the files.

After you installed the packages:
1. > Please run `bulletin_geneator.py` to generate a bulletin.
2. > Run `server.py`
3. > Wait for others to connect to the Relay with the `client.py` file

## TO-DO List
Client side:
- [ ] Better salt implementation
- [x] Better leave and join message implementation
- [x] File sharing
- [ ] Giving an option between using an already generated account, or using a randomly generated one

Server side:
- [ ] Occasionally writing the member count onto the chat (Possibly could be done client-side)
- [x] Separating the BIP39 mnemonic key and BIP32 keys generation into a separate .py file
- [x] Saving generated channel data to a `./bulletins/` directory
- [x] A channel ledger system, where the client can pick from muliple channels from said `./bulletins/` directory while connected to the server
- [ ] Solving signature error due to other members' messages

Global:
- [ ] Reworking the core authentication system from using BIP32 keys to other authentication solutions (possible standard 2FA methods as well)

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)