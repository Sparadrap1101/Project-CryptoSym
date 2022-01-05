import bcrypt
import tink
from tink import daead, cleartext_keyset_handle

database = 'database.txt'

def hash_password(pwd):
    salt = bcrypt.gensalt() # We generate a salt
    pwdHashed = bcrypt.hashpw(pwd.encode(), salt) # We hash the password using bcrypt

    return pwdHashed

def encryption_machine(msg):
    ciphertext = primitive.encrypt_deterministically(msg, assocData) # We encrypt with the primitive

    return ciphertext

def save_to_database(user, pwd):
    hashedPwd = hash_password(pwd) # We hash the password before saving

    encryptedPwd = encryption_machine(hashedPwd) # We encrypt it

    encPwdHex = encryptedPwd.hex() # Then we convert it to hex for before saving in our database (to avoid type problems later)

    file = open(database, "a") # We open our database.txt as "a" mode to add new users
    file.write(f"{user};{encPwdHex}\n") # We write our datas
    file.close()

def check_password(user, pwd):
    try:
        file = open(database, 'r') # We open our database

    except Exception as e: # if someone want to connect without having a database file yet we catch the error.
        print("\nVeuillez commencer par vous inscrire.\n")
        return False # And we return False

    for lines in file.readlines(): # We read our database
        splitLines = lines.split(";") # We split our datas

        if user == splitLines[0]: # We found the line of the corresponding user in our database
            # We decrypt the corresponding password in our database (in order to get back the hashed password)
            decryptedPwd = primitive.decrypt_deterministically(bytes.fromhex(splitLines[1]), assocData)

            # Then we compare the user password with the hashed password in our database with .checkwp()
            if bcrypt.checkpw(pwd.encode(), decryptedPwd):
                return True # Return True if it's the same

            else:
                return False # False if not

    # If the username don't correspond to anyone we return False
    return False

def inscription():
    print("\n---------------\n\nBonjour, bienvenue sur la page d'inscription. Veuillez remplir les champs ci-dessous.\n")
    user = input("Veuillez entrer votre nom d'utilisateur > ")
    pwd = input("Veuillez entrer votre mot de passe > ")

    save_to_database(user, pwd)

    print("\nMerci, vous avez bien été ajouté à notre base de donnée !\n")

def connexion():
    print("\n---------------\n\nBonjour, bienvenue sur la page de connexion. Veuillez vous connecter.\n")
    user = input("Quel est votre nom d'utilisateur ? > ")
    pwd = input("Quel est votre mot de passe ? > ")

    result = check_password(user, pwd)

    if result == True:
        print("\nFélicitations, vous êtes bien connecté !\n")

    else:
        print("\nMot de passe ou nom d'utilisateur invalide. Veuillez réessayer.\n")


if __name__ == '__main__':

    daead.register()
    fileName = "keyset.json"

    try: # We try to read the keyset.json file in order to get our key datas
        file = open(fileName, "r")
        read = tink.JsonKeysetReader(file.read())
        secret_key = cleartext_keyset_handle.read(read) # Get it in cleartext
        file.close()

    except Exception as e: # If it doesn't exist we create this file
        template_key = daead.deterministic_aead_key_templates.AES256_SIV
        secret_key = tink.new_keyset_handle(template_key) # We create a new keyset
        file = open(fileName, "w")
        write = tink.JsonKeysetWriter(file)
        cleartext_keyset_handle.write(write, secret_key) # And add it to the file
        file.close()

    primitive = secret_key.primitive(daead.DeterministicAead) # We get the primitive
    assocData = b"Here are associated data" # We add associated data for encryption

    loop = True
    while loop == True:
        print("---------------\n\nBonjour, que souhaitez vous faire ?\n\n1) Se connecter\n2) S'incrire\n3) Exit")
        answer = input("> ")

        if answer == "3": 
            break
        
        elif answer == "1":
            connexion()
        
        elif answer == "2":
            inscription()
        
        else:
            print("\nJe suis désolé, je n'ai pas compris votre requête.")