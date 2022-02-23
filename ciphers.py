"Script for encrypting/decrypting files and folders."

import os
import rsa
import string
import secrets
import hashlib as hash
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from random import randbytes, shuffle
from platform import system as get_platform
from file_encryption import AES_encrypt_file, AES_decrypt_file, BLO_encrypt_file, BLO_decrypt_file 

class NoKeyError(Exception):
    """
    Raised when no key was provided to a cipher object.
    """
    pass


class BadKeyError(Exception):
    """
    Raised when the key given does not match the encryption key signature.
    """
    pass


class InvalidCipherArgument(Exception):
    """
    Raised when a parameter for a cipher is not provided.
    """
    pass


def hash_(StringToHash=str, hash_code = str, return_type = "hex") -> str:
    """
    Miscellenious function for implementing hash algorithms.

    currently supported hashes are:
    
    SHA 224 / CODE = SHA224
    
    SHA 256 / CODE = SHA256
    
    SHA 512 / CODE = SHA512
    
    MD5 / CODE = MD5

    return_type: whether or not to return hex. specify 'bytes' if needed.
    """
    if hash_code == "SHA224":
        hash_obj = hash.sha224(StringToHash.encode())
        if return_type == "bytes":
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    if hash_code == "SHA256":
        hash_obj = hash.sha256(StringToHash.encode())
        if return_type == "bytes":
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    if hash_code == "SHA512":
        hash_obj = hash.sha512(StringToHash.encode())
        if return_type == "bytes":
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    if hash_code == "MD5":
        hash_obj = hash.md5(StringToHash.encode())
        if return_type == "bytes":
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()


def random_choice(list):
    chosen = secrets.choice(list)
    return chosen


def compare_hashes(hash_1=str, hash_2=str):
    """
    hash comparision function. 

    Takes 2 strings and compares them to see if they are the same.
    returns a boolean value in such a way to reduce timing attack efficacy.
    """
    result = secrets.compare_digest(hash_1, hash_2)
    return result


def token_generation(size=int, return_type = str):
    """
    Simplifed method for interfacing with the secrets module.

    return_type: What is being returned. modes are 'URL', 'HEX', and 'BYTES'
    
    size: the number of bytes in the token to be generated.
    """
    if return_type == "HEX":
        token = secrets.token_hex(size)
        return token
    if return_type == "BYTES":
        token = secrets.token_bytes(size)
        return token
    if return_type == "URL":
        token = secrets.token_urlsafe(size)
        return token


def gen_random_password(length:int):
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
    shuffle(characters)
    password = []
    for i in range(length):
        password.append(secrets.choice(characters))
    shuffle(password)
    final_password = "".join(password)
    return final_password


def sec_delete(file_path, random_fill = True, null_fill = True, passes = 35) -> int:
    """
    Secure file deletion function with overwriting and null filling.

    It is best practice to combine this with another secure file deletion protocol.
    """
    if "/home/" not in file_path or "/." in file_path and get_platform=="Linux":
        return 1
    else:
        with open (file_path, "wb") as file:
            data = file.read()
        length = len(data)
        if random_fill is True:
            for _ in passes:
                with open(file_path, "wb") as file:
                    file.write(randbytes(length))
        if null_fill is True:
            for _ in passes:
                with open (file_path, "wb") as file:
                    file.write("\x00" * length)
        os.system("rm {}".format(file_path))
        return 0


def delete(path):
    """
    File deletion function.
    """
    if '/home/' not in path or "/." in path:
        return 1
    else:
        os.system("rm {}".format(path))


class Ciphers:
    """
    A class for ciphering/deciphering operations.

    Linux native.

    Parameters:
        Username: The Linux username of the user who is logging in.
        Password: The password of the user.
    """


    def __init__(self, password=str) -> None:
        self.password = password
        self.marker  = b"E1m%nj2i$bhilj"


    # misc methods


    def generate_symmetric_key(self, salt=None) -> 'tuple[bytes, bytes]':
        "Method for generating keys. Will return tuple (key, salt) if salt is not provided."
        if salt is None:
            salt_ = os.urandom(32)
            key = PBKDF2(self.password, salt_, dkLen=32)
            return key, salt_
        else:
            key = PBKDF2(self.password, salt, dkLen=32)
            return key


    def generate_FerNet_key(self):
        key = Fernet.generate_key()
        return key


    def check_path_validity(self, path=str or None, decrypting=bool, type_=str) -> int:
        """
        A guard clause for file operations.

        Return codes:
            0: File path is suitable.
            1: File path is None.
            2: File path is invalid.
            3: App does not have permission to access file.
            4: File is hidden.
            5: File is part of root filesystem and not accessing chromeos.
            6: File encryption marker detected during encryption.
            7: File encryption marker not detected during decryption.
            8: File was encrypted with a different algorithm.
        """
        if path is None:
            return 1
        # checking if file is hidden
        if "/." in path:
            return 4
        # checking if file is part of the Linux root filesystem
        if get_platform() == 'Linux':
            if "/home/" not in path:
                return 5
        # checking if decrypt is cancelled
        try:
            if os.path.isfile(path) is True:
                with open (path, "rb") as file:
                    type_of_file = file.read(3)
                    file_marker = file.read(14)
            elif os.path.isdir(path) is True:
                return 0
        # checking if file exists
        except FileNotFoundError:
            return 2
        # checking if application has permission
        except PermissionError:
            return 3
        # checking if there is a file encryption marker during encryption
        if file_marker == self.marker and decrypting is False:
            return 6
        # checking if there is not a file encryption marker during decryption
        elif file_marker != self.marker and decrypting is True:
            return 7
        if decrypting is True:
            if type_of_file.decode() != type_:
                return 8
            else:
                return 0
        else:
            return 0

    
    def change_encrypting_password(self, old_password = str, new_password = str):
        if self.password == old_password:
            self.password = new_password


    # RSA methods 


    def generate_RSA_keys(self):
        "method to generate a public/private key pair for RSA encryption."
        public_key, private_key = rsa.newkeys(4096)
        return (public_key, private_key)


    def RSA_encrypt_str(self, public_key, str_=str):
        "method to encrypt a string with a RSA public key."
        encrypted_string = rsa.encrypt(str_.encode(), public_key)
        return encrypted_string


    def RSA_decrypt_str(self, private_key, encrypted_str=str):
        "Method to decrypt a string with a RSA private key."
        decrypted_string = rsa.decrypt(encrypted_str, private_key).decode()
        return decrypted_string


        # AES methods


    def AES_encrypt_file(self, path:str) -> int:
        """
        A method for encrypting a file/folder object with AES.

        Parameters:
            `path`: The path of the file/folder to be encrypted.

        Return codes:
            0: File encrypt successful.
            1: Path is None.
            2: Path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem (Linux only)
            6: File encryption marker detected during encryption.
        """
        # checking if the file path is ok
        return_code = self.check_path_validity(path, decrypting=False, type_="AES")
        if return_code != 0:
            return return_code
        AES_encrypt_file(self.password, path)
        return 0


    def AES_decrypt_file(self, path:str) -> int:
        """
        A method for decrypting an encrypted file that was encrypted with AES.

        Takes only a file path as an argument.

        return codes:
            0: File decrypt successful.
            1: Path is None.
            2: File path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem and not part of ChromeOS.
            6: File was encrypted with a different key.
            7: File was not encrypted.
            8: File was encrypted using a different alogorithm.
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=True, type_="AES")
        if return_code != 0:
            return return_code
        # passing path onto compiled Cython code
        AES_decrypt_file(self.password, path)
        return 0


    def AES_encrypt_string(self, key=None, string_to_encrypt=bytes):
        """
        Method for encrypting strings using the AES encryption alogrithm in CFB mode.

        Parameters:
            `string_to_encrypt`: the string being encrypted, in bytes
            `key`: the key to encrypt the string with. If not provided, will generate a new key using the `Ciphers` class `password` attribute.
        returns a tuple of `(ciphered_string, iv, key)`
        """
        if key is None:
            salt = os.urandom(32)
            key = self.generate_symmetric_key(salt)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphered_string = cipher.encrypt(string_to_encrypt)
        return (ciphered_string, iv, key)


    def AES_decrypt_string(self, encrypted_string:bytes, key:bytes, iv:bytes):
        """
        Method for encrypting strings using the AES encryption alogrithm in CFB mode.

        Parameters:
            `encrypted_string`: The string to be decrypted, in bytes.
            `key`: The key used to encrypt the string.
            `iv`: The Intialization vector used for encryption.
        returns the decrypted string in bytes format.
        """
        if key is None:
            raise NoKeyError("No key was provided for the cipher.")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        decrypted_string = cipher.decrypt(encrypted_string)
        return (decrypted_string)


    # Blowfish methods


    def BLO_encrypt_file(self, path:str):
        """
        A method for encrypting a file/folder object with Blowfish in CFB mode..

        Parameters:
            `path`: The path of the file/folder to be encrypted.

        Return codes:
            0: File encrypt successful.
            1: Path is None.
            2: Path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem (Linux only)
            6: File encryption marker detected during encryption.
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=False, type_="BLO")
        if return_code != 0:
            return return_code
        # passing onto cython code
        BLO_encrypt_file(self.password, path)
        return 0


    def BLO_decrypt_file(self, path=str):
        """
        A method for decrypting an encrypted file or folder that was encrypted using Blowfish.

        Parameters:
            `path`: The path of the file as a string.

        return codes:
            0: File decrypt successful.
            1: Path is None.
            2: File path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem (linux Debian based distros only).
            6: File was encrypted with a different key.
            7: File was not encrypted.
            8: File was encrypted using a different alogorithm.
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=True, type_="BLO")
        if return_code != 0:
            return return_code
        # passsing onto cython code
        BLO_decrypt_file(self.password, path)
        return 0


    def BLO_encrypt_string(self, string_to_encrypt:bytes, key=None):
        """
        Method for encrypting strings using the Blowfish encryption alogrithm in CFB mode.

        Parameters:
            `string_to_encrypt`: the string being encrypted, in bytes
            `key`: the key to encrypt the string with. If not provided, will generate a new key using the `Ciphers` class `password` attribute.
        returns a tuple of `(ciphered_string, iv, key)`
        """
        if key is None:
            salt = os.urandom(32)
            key = self.generate_symmetric_key(salt)
        iv = os.urandom(8)
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        ciphered_string = cipher.encrypt(string_to_encrypt)
        return (ciphered_string, iv, key)


    def BLO_decrypt_string(self, encrypted_string:bytes, key:bytes, iv:bytes):
        """
        Method for decrypting strings using the Blowfish encryption alogrithm in CFB mode.

        Parameters:
            `encrypted_string`: The string to be decrypted, in bytes.
            `key`: The key used to encrypt the string.
            `iv`: The Intialization vector used for encryption.
        returns the decrypted string in bytes format.
        """
        if key is None:
            raise NoKeyError("No key was provided for the cipher.")
        if iv is None:
            raise InvalidCipherArgument("No intialization vector was provided for the cipher.")
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        decrypted_string = cipher.decrypt(encrypted_string)
        return (decrypted_string)


    # FerNet methods


    def FerNet_encrypt_file(self, path:str, key=None):
        # file encryption
        if os.path.isfile(path) is True:
            #chyecking if file is suitable
            return_code = self.check_path_validity(path, decrypting=False, type_="FER")
            if return_code != 0:
                return return_code
            # generating key if no key is provided
            if key is None:
                key = self.generate_FerNet_key()
            f = Fernet(key)
            with open(path, "rb") as file:
                data = file.read()
            encrypted_data = f.encrypt(data)
            with open (path, "wb") as file:
                file.write(b"FER")
                file.write(self.marker)
                file.write(encrypted_data)
            return 0
        if os.path.isdir(path) is True:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    return_code = self.check_path_validity(file_path, decrypting=False, type_="FER")
                    if key is None:
                        key = self.generate_FerNet_key()
                    f = Fernet(key)
                    with open (file_path, "rb") as file:
                        data = file.read()
                    encrypted_data = f.encrypt(data)
                    with open(path, "wb") as file:
                        file.write(b"FER")
                        file.write(self.marker)
                        file.write(encrypted_data)
            return 0
    

    def FerNet_decrypt_file(self, path=str, key=None):
        """
        A method for decrypting an encrypted file or folder that was encrypted using FerNet.

        Parameters:
            `path`: The path of the file as a string.

            `key`: The key to encrypt the file with. Will raise a `NoKeyError` if not provided.

        return codes:
            0: File decrypt successful.
            1: Path is None.
            2: File path is invalid.
            3: App does not have permissions required to access file.
            4: File is hidden.
            5: File is part of root filesystem (linux Debian based distros only).
            6: File was encrypted with a different key.
            7: File was not encrypted.
            8: File was encrypted using a different alogorithm.
        """
        if key is None:
            raise NoKeyError("No key was provided for decryption")
        # file decryption
        if os.path.isfile(path) is True:
            return_code = self.check_path_validity(path, decrypting=True, type_="FER")
            # checking if files are suitable
            if return_code != 0:
                return return_code
            # setting cipher
            f = Fernet(key)
            # getting data from file
            with open(path, "rb") as file:
                file.read(3)
                file.read(14)
                ciphered_data = file.read()
            # decrypting and writing to file
            decrypted_data = f.decrypt(ciphered_data)
            with open(path, 'wb') as file:
                file.write(decrypted_data)
            return 0
        # directory encryption
        if os.path.isdir(path) is True:
            # looping through files
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # checking if file is suitable
                    return_code = self.check_path_validity(file_path, decrypting=True, type_="FER")
                    if return_code != 0:
                        return return_code
                    # setting cipher and getting data from file
                    f = Fernet(key)
                    with open(file_path, "rb") as file:
                        file.read(3)
                        file.read(14)
                        ciphered_data = file.read()
                    # decrypting data and writing to file
                    decrypted_data = f.decrypt(ciphered_data)
                    with open(file_path, 'wb') as file:
                        file.write(decrypted_data)
            return 0
    

    def FerNet_encrypt_string(self, key=None, bstring=bytes):
        """
        Method for encrypting a string with the `cryptography` module's `Fernet` class.

        will return a tuple of `(encrypted_text, key)` if key is not provided.
        
         will return `encrypted_text` as a `bytes` object if the key is provided.
        """
        if key is None:
            key = self.generate_FerNet_key()
            f = Fernet(key)
            encrypted_text = f.encrypt(bstring)
            return encrypted_text, key
        else:
            f = Fernet(key)
            encrypted_text = f.encrypt(bstring)
            return encrypted_text


    def FerNet_decrypt_string(self, key=bytes, encrypted_string=bytes):
        """
        Method for decryting a string with the `cryptography` module's `Fernet` class.

        Will raise a `NoKeyError` if a key for the cipher was not provided.

        Will return the decrypted text as a `bytes` object.
        """
        if key is None:
            raise NoKeyError("No key was provided for the cipher.")
        f = Fernet(key)
        decrypted_text = f.encrypt(encrypted_string)
        return decrypted_text


class Cipher_Constructor:

    def __init__(self) -> None:
        pass


    def intialize_AES_cipher(mode=str, key=None, iv=None, nonce=None) -> object:
        # this template will be used for all the modes
        if mode == "CFB":
            # guard clauses
            if iv is None:
                raise InvalidCipherArgument("Intialization vector was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            # generating cipher and returning
            cipher = AES.new(key=key, mode=AES.MODE_CFB, iv=iv)
            return cipher
        elif mode == "CBC":
            if iv is None:
                raise InvalidCipherArgument("Intialization vector was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
            return cipher
        elif mode == "CTR":
            if nonce is None:
                raise InvalidCipherArgument("Nonce was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce)
            return cipher
        elif mode == "ECB":
            if key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_ECB)
            return cipher
        elif mode == "OFB":
            if iv is None:
                raise InvalidCipherArgument("Intialization vector was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_OFB, iv=iv)
            return cipher
        elif mode == "OPENPGP":
            if iv is None:
                raise InvalidCipherArgument("Intialization vector was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_OPENPGP, iv=iv)
            return cipher
        elif mode == "CCM":
            if nonce is None:
                raise InvalidCipherArgument("Nonce was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce)
            return cipher
        elif mode == "EAX":
            if nonce is None:
                raise InvalidCipherArgument("Nonce was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
            return cipher
        elif mode == "GCM":
            if nonce is None:
                raise InvalidCipherArgument("Nonce was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
            return cipher
        elif mode == "OCB":
            if nonce is None:
                raise InvalidCipherArgument("Nonce was not provided.")
            elif key is None:
                raise NoKeyError("Key was not provided.")
            cipher = AES.new(key=key, mode=AES.MODE_OCB, nonce=nonce)
            return cipher

    
    def intialize_FerNet_cipher(key=bytes):
        """
        Returns a `Fernet` cipher object given the key.
        """
        if key is None:
            raise NoKeyError("Key was not provided.")
        fernet_cipher = Fernet(key=key)
        return fernet_cipher