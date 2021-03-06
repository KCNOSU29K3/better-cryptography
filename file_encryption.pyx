import os
import hashlib as hash
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, Blowfish
marker = b"E1m%nj2i$bhilj"

class BadKeyError(Exception):
    """
    Raised when keys do not match.
    """
    pass


def AES_encrypt_file(password:str, path:str) -> int:
    """
    A method for encrypting a file/folder object with AES.

    Parameters:
        `path`: The path of the file/folder to be encrypted.

    Return codes:
        0: File encryption successful.
    """
    # encryption for single file
    if os.path.isfile(path) is True:
        iv = os.urandom(16)
        salt = os.urandom(32)
        key = PBKDF2(password, salt, dkLen=32)
        key_hash = hash.sha256(key); key_signature = key_hash.digest()
        # getting the data and setting a cipher (using CFB to avoid padding.)
        with open (path, "rb") as file:
            data = file.read()
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        # ciphering and writing
        ciphered_data = cipher.encrypt(data)
        with open(path, "wb") as file:
            file.write(b"AES")
            file.write(marker)
            file.write(iv)
            file.write(salt)
            file.write(key_signature)
            file.write(ciphered_data)
        return 0
    # encryption for directory.
    elif os.path.isdir(path) is True:
        # looping through files in dir
        with os.scandir(path) as files:
            for single_files in files:
                salt = os.urandom(32)
                iv = os.urandom(16)
                key = PBKDF2(password, salt, dkLen=32)
                key_hash = hash.sha256(key); key_signature = key_hash.digest()
                # getting data and setting cipher
                with open (single_files, "rb") as file:
                    data = file.read()
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                # ciphering and writing.
                ciphered_data = cipher.encrypt(data)
                with open(single_files, "wb") as file:
                    file.write(b"AES")
                    file.write(marker)
                    file.write(iv)
                    file.write(salt)
                    file.write(key_signature)
                    file.write(ciphered_data)
        return 0


def AES_decrypt_file(password:str, path:str) -> int:
    """
    A method for decrypting an encrypted file that was encrypted with AES.

    Takes only a file path as an argument.

    return codes:
        0: File decrypt successful.
    """
    # decryption for single file
    if os.path.isfile(path) is True:
            # gathering needed data
        with open (path, "rb") as file:
            file.read(3)
            file.read(14)
            iv = file.read(16)
            salt = file.read(32)
            file_signature = file.read(32)
            ciphered_data = file.read()
        # building key and key hash, then comparing key hash to file signature
        key = PBKDF2(password, salt, dkLen=32)
        key_hash = hash.sha256(key); key_signature = key_hash.digest()
        if file_signature != key_signature:
            raise BadKeyError("Keys are not the same.")
        # setting cipher and decrypting the data
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        original_data = cipher.decrypt(ciphered_data)
        # writing
        with open(path, "wb") as file:
            file.write(original_data)
        return 0
    # directory decryption
    elif os.path.isdir(path) is True:
        # looping through files
        with os.scandir(path) as files:
            for single_files in files:
                # gathering needed data
                with open (single_files, "rb") as file:
                    file.read(3)
                    file.read(14)
                    iv = file.read(16)
                    salt = file.read(32)
                    file_signature = file.read(32)
                    ciphered_data = file.read()
                # building key/key hash and comparing to file signature
                key = PBKDF2(password, salt, dkLen=32)
                key_hash = hash.sha256(key); key_signature = key_hash.digest()
                if key_signature != file_signature:
                    continue
                # building the cipher and decrypting the data
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                original_data = cipher.decrypt(ciphered_data)
                # decrypting
                with open (single_files, "wb") as file:
                    file.write(original_data)
        return 0


def BLO_encrypt_file(password:str, path:str):
    """
    A method for encrypting a file/folder object with Blowfish in CFB mode..

    Parameters:
        `path`: The path of the file/folder to be encrypted.

    Return codes:
        0: File encrypt successful.
    """
    # file encryption
    if os.path.isfile(path) is True:
        # checking if file is suitable
        # generating a key, salt, and key signature
        iv = os.urandom(8) # generating IV (blowfish only takes 8)
        salt = os.urandom(32)
        key = PBKDF2(password, salt, dkLen=32)
        key_hash = hash.sha256(key); key_signature = key_hash.digest()
        # getting data and setting the cipher
        with open (path, "rb") as file:
            data = file.read()
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        # encrypting the data and writing.
        ciphered_data = cipher.encrypt(data)
        with open (path, "wb") as file:
            file.write(b"BLO")
            file.write(marker)
            file.write(iv)
            file.write(salt)
            file.write(key_signature)
            file.write(ciphered_data)
        return 0
    # directory encryption.
    elif os.path.isdir(path) is True:
        # looping through files in dir
        with os.scandir(path) as files:
            for singular_files in files:
                # checking if files are suitable
                # getting data from file
                with open(singular_files, "rb") as file:
                    data = file.read()
                # generating a key and building a key signature
                iv = os.urandom(8)
                salt = os.urandom(32)
                key = PBKDF2(password, salt, dkLen=32)
                key_hash = hash.sha256(key); key_signature = key_hash.digest()
                # setting cipher and encrypting data
                cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
                ciphered_data = cipher.encrypt(data)
                # writing
                with open(singular_files, "wb") as file:
                    file.write(b"BLO")
                    file.write(marker)
                    file.write(iv)
                    file.write(salt)
                    file.write(key_signature)
                    file.write(ciphered_data)


def BLO_decrypt_file(password:str, path:str):
    """
    A method for decrypting an encrypted file or folder that was encrypted using Blowfish.

    Parameters:
        `path`: The path of the file as a string.

    return codes:
        0: File decrypt successful.
    """
    # file decryption
    if os.path.isfile(path) is True:
        # checking if file is suitable
        # getting needed data
        with open (path, "rb") as file:
            file.read(3)
            file.read(14)
            iv = file.read(8)
            salt = file.read(32)
            file_signature = file.read(32)
            ciphered_data = file.read()
            # rebuilding the key and getting its signature
        key = PBKDF2(password, salt, dkLen=32)
        key_hash = hash.sha256(key); key_signature = key_hash.digest()
        if key_signature != file_signature:
            raise BadKeyError("Key provided was different from the one used for encryption.")
        # setting cipher and decrypting data
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        # writing
        original_data = cipher.decrypt(ciphered_data)
        with open (path, 'wb') as file:
            file.write(original_data)
        return 0
    # directory decryption
    elif os.path.isdir(path) is True:
        # looping through files
        with os.scandir(path) as files:
            for singular_files in files:
                # checking if file is suitable
                # getting data
                with open (singular_files, "rb") as file:
                    file.read(3)
                    file.read(14)
                    iv = file.read(8)
                    salt = file.read(32)
                    file_signature = file.read(32)
                    ciphered_data = file.read()
                # building key and key signature
                key = PBKDF2(password, salt, dkLen=32)
                key_hash = hash.sha256(key); key_signature = key_hash.digest()
                if key_signature != file_signature:
                    continue
                # setting the cipher and decrypting
                cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
                original_data = cipher.decrypt(ciphered_data)
                # writing the data
                with open (singular_files, "wb") as file:
                    file.write(original_data)
