import json
import base64
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import gcm
import beaupy
from pystyle import Colors, Colorate
import binascii


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
        options = ["Encrypt?", "Decrypt?", "Exit?"]
        print(f'{banner()}\n\nWhat would you like to do?\n-----------------------------------------------------------\n')
        option = beaupy.select(options, cursor_style="#ffa533")

        if not option:
            gcm.clear()
            exit("Keyboard Interuption Detected!\nGoodbye <3")


        if options[0] in option:
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

        if options[1] in option:
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

        if options[2] in option:
            gcm.clear()
            exit("Goodbye! <3")




