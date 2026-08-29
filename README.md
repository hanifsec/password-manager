# Password Manager CLI
A command-line password manager built with python.
## What it does
- Generates and checks strength of passwords.
- Add, save and retrieve passwords.
- Encrypts passwords to be saved.
- Decrypt save passwords.
- Simple CLI program, no GUI.
## How it works
- On the first run of the program the user is asked to set a master password. This password is the only password the user needs to remember and will be required whenever the user runs the program.
- There's a timeout for if the user fails to enter the correct password in 5 tries, access will be denied after timeout.
- Password generator function accepts an integer and generates a password oof that length (entering 13 would mean generator will make the password 13 characters long). It combines lowercase, uppercase, symbols/punctuation and digits to make passwords stronger.
- Password strength checker function uses zxcvbn library, which provides industry standard password strength checking. It provides A rating, warning, suggestions and crack time.
- The save_passwords function uses a key which has been derived by combining a random salt together with a hashed version of our master password. The key is used to encrypt (using Fernet) the password that has been passed in and calls load_password which saves the password in a json file. Passwords are save with names attached to then for easy identification and fetching
- The get_password function reads and fetches a given password in the json file by looking for the name of the password
## Notes
This was built as a learning project to understand encryption and to polish my previously learnt python concepts. The tool is good for personal use at best.
