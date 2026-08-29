import string, random, os, json, time, base64
from zxcvbn import zxcvbn
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_FILE = 'salt.bin'
VERIFY_FILE = 'verify.token'
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 30


def generator():
    letter_numbers = string.ascii_letters + string.digits 
    symbols = string.punctuation 
    final = ''
    
    while True:
        try:
            length = int(input('Enter desired password length \nNumbers equal to or greater than 13 are recommeded \n>>> '))
        except ValueError: # Makes sure that input given is an integer
            print('Please enter a number')
            continue

        # Quality of life option. Prevents user form generating an overly weak password
        if length < 8: 
            print('Length should be greater than 7')
            continue
        else:
            # Random set of characters are generated and joined together in size of 'length'
            final = random.choices(symbols, k=3)
            final += random.choices(letter_numbers, k=length)
            final = ''.join(random.choice(final) for i in range(length))
            print('Genearted password:', final) # Final combination is then printed out
            break
            
def strength_checker():
    password = input('Enter password: ') 
    result = zxcvbn(password) # Stores information on how zxcvbn has assessed the given password in 'result' variable
    score = result['score'] # Gets overall password score from the information in result

    # Calculates password score /10 insated of leaving it as /4
    rating = round((score / 4) * 10)
    print('* Rating: ' + str(rating))


    feedback = result['feedback']['warning'] # Tells user where/why the password is weak
    suggestions = result['feedback']['suggestions'] # Suggests how password can be imporved
    if not feedback:
        print('* Warning: None')
    else:
        print('* warning: ' + str(feedback))

    if not suggestions and score < 4:
        print('Good password, but could still be stronger.')
    elif not suggestions and score == 4:
        print('* Strong password')
    else:
        print('* Suggestions: ')
        for s in suggestions:
            print('-', s)
    print('* cracktime: ' + str(result['crack_times_display']['offline_slow_hashing_1e4_per_second']))

def derive_key(master_password, salt): # Function turns the user password into an encryption key
    kdf = PBKDF2HMAC( # Tool we are using to derive the key
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt, 
        iterations=480000, # Number of hash iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode())) 
    return key

def setup_master_password():
    salt = os.urandom(16)

    with open(SALT_FILE, 'wb') as f:
        f.write(salt)

    master_password = input('Set your master password: ')
    key = derive_key(master_password, salt)

    f = Fernet(key)
    token = f.encrypt(b'verified') # verification token

    with open(VERIFY_FILE, 'wb') as f:
        f.write(token)
        return key

def login(): 
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    attempts = 0
    while attempts < MAX_ATTEMPTS:
        master_password = input('Enter your master password: ')
        key = derive_key(master_password, salt)
        f = Fernet(key)
        with open(VERIFY_FILE, 'rb') as file:
            token = file.read()
        try:
            f.decrypt(token)
            print('Access granted')
            return key
        except InvalidToken:
            attempts += 1
            print(f'Wrong password. {MAX_ATTEMPTS - attempts} attempts remaining')
    
    print(f'Too many attempts at login. Lockout for {LOCKOUT_SECONDS} seconds')
    time.sleep(LOCKOUT_SECONDS)
    return None
        
def get_key():
    if not os.path.exists(SALT_FILE):
        return setup_master_password() # Prompts user to set password if salt does not exist
    else:
        return login() # if salt exists then user will be allowed to login

def load_password(): # Function read objects in the passwords.json file when called
    if not os.path.exists('passwords.json'): 
        return{}
    else:
        with open('passwords.json', 'r') as f:
            return json.load(f)
        
def save_password(name, password, key): # Function encrypts the password, attaches a name to it, and saves it in passwords.json file
    fernet = Fernet(key)

    encrypted = fernet.encrypt(password.encode()).decode() # Encrypts password

    passwords = load_password()
    passwords[name] = encrypted # Attaches encrypted password to the key 'name'

    with open('passwords.json', 'w') as f: 
        json.dump(passwords, f, indent=4)
    
    print(f"Password for '{name}' saved and encrypted.")
    print(f"'Encrypted password: '{encrypted}'" )

def get_password(name, key): # Function fetches specified encrypted password from the file they and saved and decrypts it
    fernet = Fernet(key)

    passwords = load_password() 

    if name not in passwords: 
        print(f"No password found for '{name}'.") # Error for if name passed in by user is not in the file
        return None
    
    encrypted = passwords[name]
    decrypted = fernet.decrypt(encrypted.encode()).decode()
    print(decrypted)

def main():
# Determines tasks to be performed based on user's input (option selected)
    key = get_key()

    if key is None:
        print('Access denied')
        return
    # Gets user input for what tasks they would like to perform
    options = input('''What would you like to do? 
A. Generate password
B. Check password strength
C. Save and encrypt password
D. Decrypt password \n>>> ''').strip().lower()

    if options == 'a':
        generator()
        time.sleep(1)
        reprompt = input('''What would you like your next action to be?
A. Check password strength
B. Save and encrypt password
C. Exit program
>>> ''').strip().lower()
        if reprompt == 'a':
            strength_checker()
        elif reprompt == 'b':
            name = input('Enter name of password: ')
            passy = input('Enter password to be encrypted: ')
            save_password(name, passy)
        else:
            print('Program exit')
    elif options == 'b':
        strength_checker()
    elif options == 'c':
        get_name = input('Enter name of password: ')
        user_password = input('Enter password to be encrypted: ')
        save_password(get_name, user_password, key)
    elif options == 'd':
            get_name = input('Enter the name of the password you want to decrypt: ')
            get_password(get_name, key)

main()