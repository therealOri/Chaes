import json
import base64
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import gcm
import beaupy
from beaupy.spinners import *
from pystyle import Colors, Colorate
import binascii
import os


def banner():
    banner = """
                 ▄▀▄▄▄▄   ▄▀▀▄ ▄▄   ▄▀▀█▄   ▄▀▀█▄▄▄▄  ▄▀▀▀▀▄
                █ █    ▌ █  █   ▄▀ ▐ ▄▀ ▀▄ ▐  ▄▀   ▐ █ █   ▐
                ▐ █      ▐  █▄▄▄█    █▄▄▄█   █▄▄▄▄▄     ▀▄
                  █         █   █   ▄▀   █   █    ▌  ▀▄   █
                 ▄▀▄▄▄▄▀   ▄▀  ▄▀  █   ▄▀   ▄▀▄▄▄▄    █▀▀▀
                █     ▐   █   █    ▐   ▐    █    ▐    ▐
                ▐         ▐   ▐             ▐
        Made by Ori#6338 | @therealOri_ | https://github.com/therealOri
    """
    colored_banner = Colorate.Horizontal(Colors.purple_to_blue, banner, 1)
    return colored_banner


chacha_header = b"ChaCha real smooth~ dada da dada da"
salt = get_random_bytes(32)


def encrypt(plaintext, eKey):
    #AES
    data_enc = gcm.stringE(enc_data=plaintext, key=eKey)
    data_enc = bytes(data_enc, 'utf-8')

    #ChaCha
    cipher = ChaCha20_Poly1305.new(key=salt)
    cipher.update(chacha_header)
    ciphertext, tag = cipher.encrypt_and_digest(data_enc)

    jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jv = [ base64.b64encode(x).decode('utf-8') for x in (cipher.nonce, chacha_header, ciphertext, tag) ]
    result = json.dumps(dict(zip(jk, jv)))
    result_bytes = bytes(result, 'utf-8')
    b64_result = base64.b64encode(result_bytes)
    final_result = base64_to_hex(b64_result)
    return final_result



def decrypt(dKey, json_input, salt):
    try:
        b64 = json.loads(json_input)
        jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:base64.b64decode(b64[k]) for k in jk}

        cipher = ChaCha20_Poly1305.new(key=salt, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    except (ValueError, KeyError):
        print("Incorrect decryption")
        return None
    #aes decrypt
    decrypted_message = gcm.stringD(dcr_data=plaintext, key=dKey)
    return decrypted_message


# Convert base64 string to hex
def base64_to_hex(base64_string):
    decoded_bytes = base64.b64decode(base64_string)
    hex_string = binascii.hexlify(decoded_bytes)
    return hex_string.decode()

# Convert hex string to base64
def hex_to_base64(hex_string):
    hex_bytes = bytes.fromhex(hex_string)
    base64_string = base64.b64encode(hex_bytes)
    return base64_string.decode()




if __name__ == '__main__':
    gcm.clear()
    while True:
        main_options = ["Encrypt?", "Decrypt?", "Exit?"]
        print(f'{banner()}\n\nWhat would you like to do?\n-----------------------------------------------------------\n')
        main_option = beaupy.select(main_options, cursor_style="#ffa533")

        if not main_option:
            gcm.clear()
            exit("Keyboard Interuption Detected!\nGoodbye <3")


        if main_options[0] in main_option:
            gcm.clear()
            while True:
                enc_options = ["Encrypt message?", "Encrypt file?", "Back?"]
                print(f'{banner()}\n\nDo you want to encrypt a message or a file?\n-----------------------------------------------------------\n')
                enc_option = beaupy.select(enc_options, cursor_style="#ffa533")

                if not enc_option:
                    gcm.clear()
                    break

                if enc_options[0] in enc_option:
                    gcm.clear()
                    message = beaupy.prompt("Message to encrypt").encode()
                    key_data = beaupy.prompt("Data for key gen").encode()

                    gcm.clear()
                    eKey = gcm.keygen(key_data) #Returns bytes and will return "None" if what's provided is less than 100 characters.

                    #Go back to main menu and continue
                    if not eKey:
                        continue

                    save_me = base64.b64encode(eKey) #for saving eKey to decrypt later.
                    bSalt = base64.b64encode(salt)
                    master_key = f"{save_me.decode()}:{bSalt.decode()}"

                    input(f'Save this key so you can decrypt later: {master_key}\n\nPress "enter" to contine...')
                    gcm.clear()

                    chaCrypt = encrypt(message, eKey)
                    gcm.clear()
                    input(f'Here is your encrypted message: {chaCrypt}\n\nPress "enter" to contine...')
                    gcm.clear()


                if enc_options[1] in enc_option:
                    gcm.clear()
                    file_path = beaupy.prompt("File to encrypt.").replace('\\', ' ').strip()
                    hex_format = "0123456789abcdefABCDEF"
                    BUFFER_SIZE = 65536  # 64KB buffer size

                    try:
                        with open(file_path, 'r') as rd:
                            while True:
                                chunk = rd.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                data_check = chunk
                    except:
                        with open(file_path, encoding='latin-1') as rd:
                            while True:
                                chunk = rd.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                data_check = chunk

                    if all(c in hex_format for c in data_check if c.isalnum()):
                        gcm.clear()
                        input('The file you have provided is already encrypted.\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue


                    if os.path.isfile(f'{file_path}.locked'):
                        gcm.clear()
                        input('The file you have provided already has the ".locked" extension.\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue
                    else:
                        with open(file_path, 'rb') as rf:
                            file_data = rf.read()

                        key_data = beaupy.prompt("Data for key gen").encode()
                        gcm.clear()
                        eKey = gcm.keygen(key_data)

                        if not eKey:
                            continue

                        save_me = base64.b64encode(eKey)
                        bSalt = base64.b64encode(salt)
                        master_key = f"{save_me.decode()}:{bSalt.decode()}"

                        input(f'Save this key so you can decrypt later: {master_key}\n\nPress "enter" to contine...')
                        gcm.clear()


                        spinner = Spinner(ARC, "Encrypting data... (this may take awhile)")
                        spinner.start()
                        chaCrypt = encrypt(file_data, eKey)
                        with open(file_path, 'w', buffering=4096*4096) as fw:
                            fw.write(chaCrypt)
                        os.rename(file_path, file_path.replace(file_path, f'{file_path}.locked'))
                        spinner.stop()
                        input(f'File has been successfully encrypted!\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue

                if enc_options[2] in enc_option:
                    gcm.clear()
                    break



        if main_options[1] in main_option:
            gcm.clear()
            while True:
                dcr_options = ["Decrypt message?", "Decrypt file?", "Back?"]
                print(f'{banner()}\n\nDo you want to decrypt a message or a file?\n-----------------------------------------------------------\n')
                dcr_option = beaupy.select(dcr_options, cursor_style="#ffa533")

                if not dcr_option:
                    gcm.clear()
                    break

                if dcr_options[0] in dcr_option:
                    #Get key and message
                    dKey = beaupy.prompt("Encryption Key")
                    dMessage = beaupy.prompt("Encrypted Message")
                    enc_message = hex_to_base64(dMessage)

                    #Decode message and get salt and key after splitting on ":" to make a list.
                    json_input = base64.b64decode(enc_message)
                    key_and_salt = dKey.split(":")
                    salt = key_and_salt[1]
                    key = key_and_salt[0]
                    salt = base64.b64decode(salt)
                    key = base64.b64decode(key)

                    #Decrypt data.
                    cha_aes_crypt = decrypt(key, json_input, salt)
                    gcm.clear()
                    input(f'Here is your encrypted message: {cha_aes_crypt}\n\nPress "enter" to contine...')
                    gcm.clear()
                    continue

                if dcr_options[1] in  dcr_option:
                    file_path = beaupy.prompt("File to decrypt").replace('\\', ' ').strip()
                    hex_format = "0123456789abcdefABCDEF"
                    BUFFER_SIZE = 65536  # 64KB buffer size

                    try:
                        with open(file_path, 'r') as rd:
                            while True:
                                chunk = rd.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                data_check = chunk
                    except:
                        with open(file_path, encoding='latin-1') as rd:
                            while True:
                                chunk = rd.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                data_check = chunk

                    if not all(c in hex_format for c in data_check if c.isalnum()):
                        gcm.clear()
                        input('The file you have provided does not match encrypted format - (hexadecimal).\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue


                    if file_path.endswith(".locked"):
                        dKey = beaupy.prompt("Encryption Key")
                        with open(file_path, 'r') as fr:
                            file_data = fr.read()
                        enc_message = hex_to_base64(file_data)

                        json_input = base64.b64decode(enc_message)
                        key_and_salt = dKey.split(":")
                        salt = key_and_salt[1]
                        key = key_and_salt[0]
                        salt = base64.b64decode(salt)
                        key = base64.b64decode(key)

                        spinner = Spinner(ARC, "Decrypting data... (this may take awhile)")
                        spinner.start()
                        cha_aes_crypt = decrypt(key, json_input, salt)
                        with open(file_path, 'wb', buffering=4096*4096) as fw:
                            fw.write(cha_aes_crypt)
                        os.rename(file_path, file_path.replace('.locked', ''))
                        spinner.stop()

                        input(f'File has been successfully decrypted!\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue
                    else:
                        gcm.clear()
                        input('The file you have provided does not have the ".locked" extension.\n\nPress "enter" to continue...')
                        gcm.clear()
                        continue

                if dcr_options[2] in dcr_option:
                    gcm.clear()
                    break



        if main_options[2] in main_option:
            gcm.clear()
            exit("Goodbye! <3")


