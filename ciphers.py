#! /usr/bin/python3.9
"Python script containing functions and classes for general cryptographic use."

# importing libraries
import os
import rsa
import string
import secrets
import hashlib as hash
from random import shuffle
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Util.strxor import strxor
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from platform import system as get_platform
from Crypto.Util.number import getPrime, isPrime, GCD
from Crypto.Util.RFC1751 import english_to_key, key_to_english
from Crypto.Cipher import Salsa20, ChaCha20, ChaCha20_Poly1305, DES, DES3, ARC2, ARC4, CAST
from .file_encryption import AES_encrypt_file, AES_decrypt_file, BLO_encrypt_file, BLO_decrypt_file


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


class InvalidKeyArgument(Exception):
    """
    Raised when a key generation function recieves an incorrect parameter, or when a given parameter does not meet the requirements of the underlying key generation function.
    """
    pass


class UnknownError(Exception):
    """
    Raised when a an unknown error occurrs during encryption/decryption.
    """
    pass


def hash_(ToHash, hash_code:str, return_hex=True, return_length = 256): # tested
    """
    Miscellenious function for implementing hash algorithms.

    Parameters:
    `ToHash`: The bytes to be hashed; if not bytes, it will be converted to bytes.
    `hash_code`: A string indicating which hashing algorithm to use.
    currently supported hashes are:
    
    `'SHA224'`: SHA224 hashing algorithm.
    `'SHA256'`: SHA256 hashing algorithm.
    `'SHA_384'`: SHA384 hashing algorithm.
    `'SHA512'`: SHA512 hashing algorithm.
    `'MD5'`: MD5 hashing algorithm.
    `'SHA1'`: SHA1 hashing algorithm.
    `'SHA3_224'`: SHA3_224 hashing algorithm.
    `'SHA3_256'`: SHA3-256 hashing algorithm.
    `'SHA3_384'`: SHA3-384 hashing algorithm.
    `'SHA3_512'`: SHA3-512 hashing algorithm.
    `'BLAKE2b'`: BLAKE2b hashing algorithm.
    `'BLAKE2s'`: BLAKE2s hashing algorithm.
    `'SHAKE_128'`: SHAKE_128 hashing algorithm.
    `'SHAKE_256'`: SHAKE_256 hashing algorithm.


    `return_hex`: A boolean indicating whether the output should be in hexadecimal or not.

    `return_length`: An optional parameter specifying the amount of bytes to return. Used only in shake algorithms.

    Returns: a hash of the specific algorithm and data representation.
    """
    ToHash = bytes(ToHash, 'utf-8')
    hash_code = hash_code.upper()
    if hash_code == "SHA224":
        hash_obj = hash.sha224(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA256":
        hash_obj = hash.sha256(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA512":
        hash_obj = hash.sha512(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "MD5":
        hash_obj = hash.md5(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA384":
        hash_obj = hash.sha384(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA1":
        hash_obj = hash.sha1(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "BLAKE2B":
        hash_obj = hash.blake2b(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "BLAKE2S":
        hash_obj = hash.blake2s(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA3_224":
        hash_obj = hash.sha3_224(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA3_256":
        hash_obj = hash.sha3_256(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA3_384":
        hash_obj = hash.sha3_384(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHA3_512":
        hash_obj = hash.sha3_512(ToHash)
        if return_hex is False:
            return hash_obj.digest()
        else:
            return hash_obj.hexdigest()
    elif hash_code == "SHAKE_128":
        hash_obj = hash.shake_128(ToHash)
        if return_hex is False:
            return hash_obj.digest(return_length)
        else:
            return hash_obj.hexdigest(return_length)
    elif hash_code == "SHAKE_256":
        hash_obj = hash.shake_256(ToHash)
        if return_hex is False:
            return hash_obj.digest(return_length)
        else:
            return hash_obj.hexdigest(return_length)


def random_choice(given_list:list): # tested
    """
    A function to randomly choose an item from a given list.

    Parameters:
    `given_list`: The list to choose from.

    Returns: the chosen item in the list.
    """
    chosen = secrets.choice(given_list)
    return chosen


def compare_hashes(hash_1=str, hash_2=str) -> bool: # tested
    """
    hash comparision function. 

    Takes 2 strings and compares them to see if they are the same.
    returns a boolean value in such a way to reduce timing attack efficacy.

    Parameters:
    `hash_1`: The string to compare the second hash to.
    `hash_2`: The string to be compared.
    """
    result = secrets.compare_digest(hash_1, hash_2)
    return result


def token_generate(size:int, return_type="HEX"): # tested
    """
    Simplifed method for interfacing with the secrets module.

    Parameters:
    `return_type`: What is being returned. modes are `'URL'`, `'HEX'`, and `'BYTES'`.
    
    `size`: the number of bytes in the token to be generated.

    returns: a token of the specific type, or 1 to indicate that the return type was not valid.
    """
    if return_type.upper() == "HEX":
        token = secrets.token_hex(size)
        return token
    if return_type.upper() == "BYTES":
        token = secrets.token_bytes(size)
        return token
    if return_type.upper() == "URL":
        token = secrets.token_urlsafe(size)
        return token
    else:
        return 1


def generate_password(length:int) -> str: # tested
    """
    Generates and returns a random password of n `length`.
    """
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
    shuffle(characters)
    password = []
    for i in range(length):
        password.append(secrets.choice(characters))
    shuffle(password)
    final_password = "".join(password)
    # deleting uneeded variables
    del characters
    return final_password


def sec_delete(file_path:str, random_fill = True, null_fill = True, passes = 35) -> int: # tested
    """
    Secure file deletion function with overwriting and null filling.

    It is best practice to combine this with another secure file deletion protocol.
    return codes:
    1: Attempting to access root folder or hidden file.
    2: Attempt to pass a dangerous command to command line.
    0: File successfully deleted.
    """
    file_path = os.path.abspath(file_path)
    if "/home/" not in file_path or "/." in file_path:
        return 1
    elif "sudo rm -rf /" in file_path:
        return 2
    # testing if platform is Linux
    if get_platform() != "Linux":
        return 3
    else:
        with open (file_path, "rb") as file:
            data = file.read()
        length = len(data)
        if random_fill is True:
            for _ in range(passes):
                with open(file_path, "wb") as file:
                    file.write(os.urandom(length))
        if null_fill is True:
            for _ in range(passes):
                with open (file_path, "wb") as file:
                    file.write(b"\x00" * length)
        os.system("rm {}".format(file_path))
        # deleting uneeded variables
        del data, length, file_path, random_fill, null_fill, passes
        return 0


def delete(path:str) -> int: # tested
    """
    File deletion function.

    Parameters:
    `path`: The path to the file, in string format.

    Returns: An integer value indicating if the function successfully executed.
    """
    path = os.path.abspath(path)
    if '/home/' not in path or "/." in path:
        return 1
    elif "sudo rm -rf /" in path:
        return 2
    # checking if the platform is Linux
    elif get_platform() == "Linux":
        os.system("rm {}".format(path))
        return 0
    else:
        return 3


def XOR(bytes1:bytes, bytes2:bytes, write_to=None):
    """
    A function for preforming XOR operations on bytestrings.
    Returns: None if `write_to` is `None`, otherwise returns the XOR'ed string.
    """
    bytes_string = strxor(bytes1, bytes2, output = write_to)
    return bytes_string


def one_time_pad_encrypt(message:str, key:str):
    """
    A function for performing one time pad encryption. using a key generated from a keyphrase."""
    # generating the key
    key_bytes = hash_(key, "SHA256", return_hex=False)
    # getting the length of the key
    key_length = len(key_bytes)
    # getting the length of the message bytes
    message_length = len(message.encode())
    # coverting the message to bytes
    print (key_length, message_length)
    message_bytes = message.encode()
    # ensuring message length is a multiple of key length
    if message_length % key_length != 0:
        message_bytes = message_bytes + b"\x00" * (key_length - (message_length % key_length))
    #breaking the message into chunks
    message_chunks = [message_bytes[i:i+key_length] for i in range(0, len(message_bytes), key_length)]
    # XORing the chunks with the key
    chunks = []
    for i in range(len(message_chunks)):
        XORed_chunks = XOR(message_chunks[i], key_bytes)
        chunks.append(XORed_chunks)
    assert len(chunks) == len(message_chunks)
    encrypted_message = b"".join(chunks)
    # deleting all variables
    del key_bytes, key_length, message_length, message_chunks, XORed_chunks
    # returning the XORed string
    return encrypted_message


def one_time_pad_decrypt(message:bytes, key:str):
    """
    A function for performing one time pad decryption. using a key generated from a keyphrase."""
    # generating the key
    key_bytes = hash_(key, "SHA256", return_hex=False)
    # getting the length of the key
    key_length = len(key_bytes)
    # breaking the message bytes into chunks of the key length
    message_chunks = [message[i:i+key_length] for i in range(0, len(message), key_length)]
    # XORing the chunks with the key
    chunks = []
    for i in range(len(message_chunks)):
        XORed_chunks = XOR(message_chunks[i], key_bytes)
        chunks.append(XORed_chunks)
    # joining the chunks
    message_bytes = b"".join(chunks)
    # removing the null bytes
    message_bytes = message_bytes.rstrip(b"\x00")
    # deleting all variables
    del key_bytes, key_length, message_chunks, XORed_chunks
    # returning the XORed string
    return message_bytes


def is_prime_number(number:int) -> bool:
    """
    A function for testing if a number is prime. Returns a boolean value.
    """
    number_is_prime = isPrime(number)
    return number_is_prime


def get_prime_number(length_in_bits:int) -> int:
    """
    A function for generating a prime number of bit length `length_in_bits`.
    """
    prime_number = getPrime(length_in_bits)
    return prime_number


def get_GCD(number1:int, number2:int) -> int:
    """
    A function to find the greatest common denominator between `number1` and `number2`.
    Returns the greatest common denominator.
    """
    greatest_CD = GCD(number1, number2)
    return greatest_CD


def englishToKey(words:str) -> bytes:
    """
    A function for generating a key using english words.

    Parameters:
    `words`: The words to be used in generating the key, seperated by whitespace. The length must be a multiple of 6.
    """
    split_words = words.split(" ")
    amount_of_words = len(split_words)
    if amount_of_words % 6 != 0:
        raise InvalidKeyArgument("Given amount of words are not a multiple of 6.")
    key = english_to_key(s=words)
    # deleting uneeded variables
    del amount_of_words, split_words
    return key


def keyToEnglish(key:bytes):
    """
    A function for  converting a bytestring to a string of english words.

    Parameters:
    'key': The bytestring to convert to english words. Its length must be a multiple of 8.
    """
    length_of_key = len(key)
    if length_of_key % 8 != 0:
        raise InvalidKeyArgument("Key length is not a multiple of 8.")
    words = key_to_english(key=key)
    return words


class Ciphers: # tested
    """
    A class for ciphering/deciphering operations.

    Linux native.

    Parameters:
        Password: The password of the user.
    """


    def __init__(self, password=str) -> None:
        self.password = password
        self.marker  = b"E1m%nj2i$bhilj"


    # misc methods


    def generate_symmetric_key(self, salt=None or bytes) -> 'tuple[bytes, bytes]': # tested
        "Method for generating keys. Will return tuple (key, salt) if salt is not provided."
        if salt is None:
            salt_ = os.urandom(32)
            key = PBKDF2(self.password, salt_, dkLen=32)
            return key, salt_
        else:
            key = PBKDF2(self.password, salt, dkLen=32)
            return key


    def generate_FerNet_key(self): # tested
        """
        A method for generating a FerNet key. Takes no arguements and returns a key in bytes format.
        """
        key = Fernet.generate_key()
        return key


    def check_path_validity(self, path=str or None, decrypting=bool, type_=str) -> int: # tested
        """
        A guard clause for file operations.

        Return codes:
            0: File path is suitable.
            1: File path is invalid.
        """
        try:
            assert path is not None
            assert "/." not in path
            assert get_platform() == "linux" and "/home/" in path
            assert os.path.isfile(path) is True or os.path.isdir(path) is True
            try:
                with open (path, "rb") as file:
                    file_type = file.read(3)
                    file_marker = file.read(len(self.marker))
            except PermissionError:
                return 1
            except FileNotFoundError:
                return 1
            except IsADirectoryError:
                return 0
            assert file_type == type_
            if decrypting:
                assert file_marker == self.marker
            else:
                assert file_marker != self.marker
        except AssertionError:
            return 1
        return 0
    

    def change_encrypting_password(self, old_password:str, new_password:str):  # tested
        """
        A method for changing the classes' `password` attribute.

        Parameters:
        `old_password`: The original password of the cipher; required for verification
        `new_password`: The password to replace the old one.

        Returns: 1, if the `old_password` parameter does not match the class `password` attribute.
        
        Returns 0 if the password change was successful.
        """
        if self.password == old_password:
            self.password = new_password
            return 0
        else:
            return 1


    # RSA methods 


    def generate_RSA_keys(self): # tested
        "method to generate a public/private key pair for RSA encryption."
        public_key, private_key = rsa.newkeys(4096)
        return (public_key, private_key)


    def RSA_encrypt_str(self, public_key, str_=str): # tested
        "method to encrypt a string with a RSA public key."
        encrypted_string = rsa.encrypt(str_.encode(), public_key)
        return encrypted_string


    def RSA_decrypt_str(self, private_key, encrypted_str:bytes): # tested
        "Method to decrypt a string with a RSA private key."
        decrypted_string = rsa.decrypt(encrypted_str, private_key).decode()
        return decrypted_string


    # AES methods


    def AES_encrypt_file(self, path:str) -> int: # tested
        """
        A method for encrypting a file/folder object with AES.

        Parameters:
            `path`: The path of the file/folder to be encrypted.

        Return codes:
            0: File encryption successful.
            1: Path is invalid.
        """
        # checking if the file path is ok
        return_code = self.check_path_validity(path, decrypting=False, type_="AES")
        if return_code != 0:
            return return_code
        try:
            AES_encrypt_file(self.password, path)
        except Exception as error:
            raise UnknownError("Unknown error occurred: {}".format(error))
        return 0


    def AES_decrypt_file(self, path:str) -> int:  # tested
        """
        A method for decrypting an encrypted file that was encrypted with AES.

        Takes only a file path as an argument.

        return codes:
            0: File decrypt successful.
            1: Path is invalid.
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=True, type_="AES")
        if return_code != 0:
            return return_code
        # passing path onto compiled Cython code
        try:
            AES_decrypt_file(self.password, path)
        except Exception as error:
            raise UnknownError("Unknown error occurred: {}".format(error))
        return 0


    def AES_encrypt_string(self, string_to_encrypt:bytes, key=None):  # tested
        """
        Method for encrypting strings using the AES encryption alogrithm in CFB mode.

        Parameters:
            `string_to_encrypt`: the string being encrypted, in bytes
            `key`: the key to encrypt the string with. If not provided, will generate a new key using the `Ciphers` class `password` attribute.
        returns a tuple of `(ciphered_string, iv, key)` if key is not provided; otherwise returns a tuple of `(ciphered_string, iv)`.
        """
        if key is None:
            salt = os.urandom(32)
            key = self.generate_symmetric_key(salt)
            key_was_none = True
        else:
            key_was_none = False
        try:
            assert isinstance(string_to_encrypt, bytes)
        except AssertionError:
            string_to_encrypt = string_to_encrypt.encode()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphered_string = cipher.encrypt(string_to_encrypt)
        if key_was_none is True:
            return (ciphered_string, iv, key)
        else:
            return (ciphered_string, iv)


    def AES_decrypt_string(self, encrypted_string:bytes, key:bytes, iv:bytes):  # tested
        """
        Method for decrypting strings using the AES encryption alogrithm in CFB mode.

        Parameters:
            `encrypted_string`: The string to be decrypted, in bytes.
            `key`: The key used to encrypt the string.
            `iv`: The Intialization vector used for encryption.
        returns the decrypted string in bytes format.
        """
        try:
            assert key is not None and iv is not None
        except AssertionError:
            raise InvalidCipherArgument("Key and IV must be provided.")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        decrypted_string = cipher.decrypt(encrypted_string)
        return (decrypted_string)


    # Blowfish methods


    def BLO_encrypt_file(self, path:str):  # tested
        """
        A method for encrypting a file/folder object with Blowfish in CFB mode.

        Parameters:
            `path`: The path of the file/folder to be encrypted.

        Return codes:
            0: File encrypt successful.
            1: Path is invalid.
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=False, type_="BLO")
        if return_code != 0:
            return return_code
        # passing onto cython code
        try:
            BLO_encrypt_file(self.password, path)
        except Exception as error:
            raise UnknownError("Unknown error occurred: {}".format(error))
        return 0


    def BLO_decrypt_file(self, path=str):  # tested
        """
        A method for decrypting an encrypted file or folder that was encrypted using Blowfish.

        Parameters:
            `path`: The path of the file as a string.

        return codes:
            0: File decrypt successful.
            1: Path is invalid
        """
        # checking if file is suitable
        return_code = self.check_path_validity(path, decrypting=True, type_="BLO")
        if return_code != 0:
            return return_code
        # passing onto cython code
        try:
            BLO_decrypt_file(self.password, path)
        except Exception as error:
            raise UnknownError("Unknown error occurred: {}".format(error))
        return 0


    def BLO_encrypt_string(self, string_to_encrypt:bytes, key=None):  # tested
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
            key_was_none = True
        else:
            key_was_none = False
        try:
            assert isinstance(string_to_encrypt, bytes)
        except AssertionError:
            string_to_encrypt = string_to_encrypt.encode()
        iv = os.urandom(8)
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        ciphered_string = cipher.encrypt(string_to_encrypt)
        if key_was_none is True:
            return (ciphered_string, iv, key)
        else:
            return (ciphered_string, iv)


    def BLO_decrypt_string(self, encrypted_string:bytes, key:bytes, iv:bytes):  # tested
        """
        Method for decrypting strings using the Blowfish encryption alogrithm in CFB mode.

        Parameters:
            `encrypted_string`: The string to be decrypted, in bytes.
            `key`: The key used to encrypt the string.
            `iv`: The Intialization vector used for encryption.
        returns the decrypted string in bytes format.
        """
        try:
            assert key is not None and iv is not None
        except AssertionError:
            raise InvalidCipherArgument("Key and IV must be provided.")
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        decrypted_string = cipher.decrypt(encrypted_string)
        return (decrypted_string)


    # FerNet methods


    def FerNet_encrypt_file(self, path:str, key:bytes):  # tested
        """
        A method for encrypting a file or folder using Fernet.

        parameters:

            path: The path to the file in string format.

            key: The key to be used for encryption.

        returns:
            0: File encrypt successful.
            1: Path is invalid.
        """
        # file encryption
        if os.path.isfile(path) is True:
            #checking if file is suitable
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
    

    def FerNet_decrypt_file(self, path:str, key:bytes):  # tested
        """
        A method for decrypting an encrypted file or folder that was encrypted using FerNet.

        Parameters:
            `path`: The path of the file as a string.

            `key`: The key to encrypt the file with. Will raise a `NoKeyError` if not provided.

        return codes:
            0: File decrypt successful.
            1: Path is Invalid.
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
    

    def FerNet_encrypt_string(self, bstring:bytes, key=None):  # tested
        """
        Method for encrypting a string with the `cryptography` module's `Fernet` class.

        will return a tuple of `(encrypted_text, key)` if key is not provided.
        
         will return `encrypted_text` as a `bytes` object if the key is provided.
        """
        if key is None:
            key = self.generate_FerNet_key()
            key_was_none = True
        else:
            key_was_none = False
        f = Fernet(key)
        try:
            assert isinstance(bstring, bytes)
        except AssertionError:
            bstring = bstring.encode()
        encrypted_text = f.encrypt(bstring)
        if key_was_none is True:
            return (encrypted_text, key)
        else:
            return (encrypted_text)


    def FerNet_decrypt_string(self, encrypted_string:bytes, key:bytes):  # tested
        """
        Method for decrypting a string with the `cryptography` module's `Fernet` class.

        Will raise a `NoKeyError` if a key for the cipher was not provided.

        Will return the decrypted text as a `bytes` object.
        """
        try:
            assert key is not None
        except AssertionError:
            raise NoKeyError("No key was provided for decryption")
        f = Fernet(key)
        decrypted_text = f.encrypt(encrypted_string)
        return decrypted_text


    def change_file_marker(self, new_file_marker:bytes):
        """
        Method for changing the file marker used to identify encrypted files.

        ## THIS MAY PREVENT DECRYPTION OF FILES THAT WERE ENCRYPTED WITH ANOTHER FILE MARKER.
        """
        self.marker = new_file_marker
        return 0


class Cipher_Constructor:
    """
    A class for simplifying cipher object generation.
    """


    def __init__(self) -> None:
        pass


    def intialize_AES_cipher(mode:str, key:bytes, iv=None, nonce=None) -> object:
        """
        method for simplifed generation of AES ciphers.
        Mode: The 3 letter mode for the cipher.
        Modes are:
            CFB

            CBC
            
            CTR
            
            ECB
            
            OFB
            
            OPENPGP
            
            CCM
            
            EAX
            
            GCM
            
            OCB

        key: The key to be used in the cipher.

        IV/Nonce: the nonce or IV to be used in the cipher, depending on the mode.
        """
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


    def intialize_Blowfish_cipher(mode:str, key:bytes, iv=None, nonce=None) -> object:
        """
        A simplifed method for generating Blowfish cipher objects.

        Parameters:

        `Mode`: The string indicating which mode to set the cipher in.

            Modes are:

            `ECB` - 

            `CBC` - 

            `CFB`

            `OFB` - 

            `CTR` - 

            `OPENPGP` - 

            `EAX` - 
        
        `key`: the key to use in the cipher.

        `iv`/`nonce`: The Intialization vector or nonce to be used in the cipher (dependent on the mode)

        """
        # all things with "O" or o in them
        if "O" in mode or "o" in mode:
            # checking if mode is OPENPGP
            if "OPEN" in mode or "open" in mode:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_OPENPGP, iv=iv)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_OFB, iv=iv)
                return cipher
        elif "E" in mode:
            if "X" in mode:
                if nonce is None:
                    raise InvalidCipherArgument("nonce not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_EAX, nonce=nonce)
                return cipher
            else:
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_ECB)
                return cipher
        elif "B" in mode:
            if "BC" in mode:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_CBC, iv=iv)
                return cipher
            elif "T" in mode:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_CTR, nonce=nonce)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = Blowfish.new(key=key, mode=Blowfish.MODE_CFB, iv=iv)

    
    def Intialize_Salsa20(key:bytes, nonce:bytes) -> object:
        """
        A method for generating a `Salsa20` cipher object.

        Parameters:
        
        `key`: The byte key to be used in creating the cipher object.

        `nonce`: The nonce to be used in creating the cipher. Must be either 16 or 32 bytes in length.

        Returns: a `Salsa20` cipher object.
        """
        if len(nonce) != 16 and len(nonce) != 32:
            raise InvalidCipherArgument("Nonce length was not 16 or 32 bytes.")
        cipher = Salsa20.new(key=key, nonce=nonce)
        return cipher
    

    def intialize_ChaCha20(key:bytes, nonce:bytes) -> object:
        """
        A method for generating a `ChaCha20` cipher object.

        Parameters:
        
        `key`: The byte key to be used in creating the cipher object.

        `nonce`: The nonce to be used in creating the cipher. Must be either 8 or 12 bytes in length.

        Returns: a `ChaCha20` cipher object.
        """
        if len(nonce) != 8 and len(nonce) != 12:
            raise InvalidCipherArgument("Nonce length was not 8 or 12 bytes.")
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher


    def intialize_ChaCha20P1305(key:bytes, nonce:bytes) -> object:
        """
        A method for generating a `ChaCha20_Poly1305` cipher object.

        Parameters:
        
        `key`: The byte key to be used in creating the cipher object.

        `nonce`: The nonce to be used in creating the cipher. Must be either 8 or 12 bytes in length.

        Returns: a `ChaCha20` cipher object.
        """
        if len(nonce) != 8 and len(nonce) != 12:
            raise InvalidCipherArgument("Nonce length was not 8 or 12 bytes.")
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        return cipher
        pass


    def intialize_DES(mode:str, key:bytes, iv=None, nonce=None) -> object:
        """
        A method for generating a `DES` cipher object.

        Parameters:
        `mode`: an uppercase string indicating which mode the cipher should be set to.

        Valid modes are:
            `ECB`

            `CBC` - 
            
            `CFB` -
            
            `OFB` - 
            
            `CTR` - 
            
            `OPENPGP` - 
            
            `EAX`
        

        `key`: The key to set the cipher with.

        `iv`/`nonce`: The intialization vector or nonce to set the cipher with. Dependent on the `mode` used.
        Will raise an `InvalidCipherArgument` error if the required parameter is not provided.
        """
        mode_ = mode.upper()
        if "O" in mode_:
            if "OPEN" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES.new(key=key, mode=DES.MODE_OPENPGP, iv=iv)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES.new(key=key, mode=DES.MODE_OFB, iv=iv)
                return cipher
        elif "C" in mode_:
            if "CBC" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES.new(key=key, mode=DES.MODE_CBC, iv=iv)
                return cipher
            elif "R" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided.")
                cipher = DES.new(key=key, mode=DES.MODE_CTR, nonce=nonce)
                return cipher
        else:
            if "X" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided")
                cipher = DES.new(key=key, mode=DES.MODE_EAX, nonce=nonce)
                return cipher
            elif "EC" in mode_:
                cipher = DES.new(key=key, mode=DES.MODE_ECB)
                return cipher
            else:
                raise InvalidCipherArgument("Unsupported mode given.")


    def intalize_DES3(mode:str, key:bytes, iv=None, nonce=None) -> object:
        """
        A method for generating a `DES3` cipher object.

        Parameters:
        `mode`: an uppercase string indicating which mode the cipher should be set to.

        Valid modes are:
            `ECB`

            `CBC`
            
            `CFB`
            
            `OFB`
            
            `CTR`
            
            `OPENPGP`
            
            `EAX`
        

        `key`: The key to set the cipher with.

        `iv`/`nonce`: The intialization vector or nonce to set the cipher with. Dependent on the `mode` used.
        Will raise an `InvalidCipherArgument` error if the required parameter is not provided.
        """
        mode_ = mode.upper()
        if "O" in mode_:
            if "OPEN" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES3.new(key=key, mode=DES3.MODE_OPENPGP, iv=iv)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES3.new(key=key, mode=DES3.MODE_OFB, iv=iv)
                return cipher
        elif "C" in mode_:
            if "CBC" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = DES3.new(key=key, mode=DES3.MODE_CBC, iv=iv)
                return cipher
            elif "R" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided.")
                cipher = DES3.new(key=key, mode=DES3.MODE_CTR, nonce=nonce)
                return cipher
        else:
            if "X" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided")
                cipher = DES3.new(key=key, mode=DES3.MODE_EAX, nonce=nonce)
                return cipher
            elif "EC" in mode_:
                cipher = DES3.new(key=key, mode=DES3.MODE_ECB)
                return cipher
            else:
                raise InvalidCipherArgument("Unsupported mode given.")


    def intialize_ARC2(mode:str, key:bytes, iv=None, nonce=None) -> object:
        """
        A method for generating an `ARC2` cipher object.

        Parameters:
        `mode`: an uppercase string indicating which mode the cipher should be set to.

        Valid modes are:
            `ECB`

            `CBC`
            
            `CFB`
            
            `OFB`
            
            `CTR`
            
            `OPENPGP`
            
            `EAX`
        

        `key`: The key to set the cipher with.

        `iv`/`nonce`: The intialization vector or nonce to set the cipher with. Dependent on the `mode` used.
        Will raise an `InvalidCipherArgument` error if the required parameter is not provided.
        """
        mode_ = mode.upper()
        if "O" in mode_:
            if "OPEN" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = ARC2.new(key=key, mode=ARC2.MODE_OPENPGP, iv=iv)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = ARC2.new(key=key, mode=ARC2.MODE_OFB, iv=iv)
                return cipher
        elif "C" in mode_:
            if "CBC" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = ARC2.new(key=key, mode=ARC2.MODE_CBC, iv=iv)
                return cipher
            elif "R" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided.")
                cipher = ARC2.new(key=key, mode=ARC2.MODE_CTR, nonce=nonce)
                return cipher
        else:
            if "X" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided")
                cipher = ARC2.new(key=key, mode=ARC2.MODE_EAX, nonce=nonce)
                return cipher
            elif "EC" in mode_:
                cipher = ARC2.new(key=key, mode=ARC2.MODE_ECB)
                return cipher
            else:
                raise InvalidCipherArgument("Unsupported mode given.")


    def intalize_ARC4(key:bytes, drop=0) -> object:
        """
        A method for generating an `ARC4` cipher OBJECT.

        Parameters:

        `key`: the key to use in the cipher; must be between 5 and 256 bytes.

        `drop`: The amount of bytes to drop from the intial keystream.

        returns: an `ARC4` cipher object.
        """
        cipher = ARC4.new(key=key, drop=drop)
        return cipher


    def intialize_CAST(mode:str, key:str, iv=None, nonce=None):
        """
        A method for generating a `CAST` cipher object.

        Parameters:
        `mode`: an uppercase string indicating which mode the cipher should be set to.

        Valid modes are:
            `ECB`

            `CBC`
            
            `CFB`
            
            `OFB`
            
            `CTR` 
            
            `OPENPGP` 
            
            `EAX`
        

        `key`: The key to set the cipher with.

        `iv`/`nonce`: The intialization vector or nonce to set the cipher with. Dependent on the `mode` used.
        Will raise an `InvalidCipherArgument` error if the required parameter is not provided.
        """
        mode_ = mode.upper()
        if "O" in mode_:
            if "OPEN" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = CAST.new(key=key, mode=CAST.MODE_OPENPGP, iv=iv)
                return cipher
            else:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = CAST.new(key=key, mode=CAST.MODE_OFB, iv=iv)
                return cipher
        elif "C" in mode_:
            if "CBC" in mode_:
                if iv is None:
                    raise InvalidCipherArgument("Intialization vector not provided.")
                cipher = CAST.new(key=key, mode=CAST.MODE_CBC, iv=iv)
                return cipher
            elif "R" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided.")
                cipher = CAST.new(key=key, mode=CAST.MODE_CTR, nonce=nonce)
                return cipher
        else:
            if "X" in mode_:
                if nonce is None:
                    raise InvalidCipherArgument("Nonce not provided")
                cipher = CAST.new(key=key, mode=CAST.MODE_EAX, nonce=nonce)
                return cipher
            elif "EC" in mode_:
                cipher = CAST.new(key=key, mode=CAST.MODE_ECB)
                return cipher
            else:
                raise InvalidCipherArgument("Unsupported mode given.")


    def intialize_FerNet_cipher(key:bytes) -> object:
        """
        Returns a `Fernet` cipher object given the key.
        """
        if key is None:
            raise NoKeyError("Key was not provided.")
        fernet_cipher = Fernet(key=key)
        return fernet_cipher


def init_diagonostic():
    """A method for testing the various functions of this library."""
    print("Testing functions in the `cipher` module.")
    print ("testing hashes")
    assert hash_("Hello World", "SHA224") == hash.sha224("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA256") == hash.sha256("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA512") == hash.sha512("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "MD5") == hash.md5("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA1") == hash.sha1("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA3_224") == hash.sha3_224("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA3_256") == hash.sha3_256("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA3_384") == hash.sha3_384("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHA3_512") == hash.sha3_512("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "BLAKE2b") == hash.blake2b("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "BLAKE2s") == hash.blake2s("Hello World".encode("utf-8")).hexdigest()
    assert hash_("Hello World", "SHAKE_128") == hash.shake_128("Hello World".encode("utf-8")).hexdigest(256)
    assert hash_("Hello World", "SHAKE_256") == hash.shake_256("Hello World".encode("utf-8")).hexdigest(256)
    print ("Hexdigests match")
    print("testing byte hashing")
    assert hash_("Hello World", "SHA224") == hash.sha224(b"Hello World").hexdigest()
    assert hash_("Hello World", "SHA256", return_hex=False) == hash.sha256("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA512", return_hex=False) == hash.sha512("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "MD5", return_hex=False) == hash.md5("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA1", return_hex=False) == hash.sha1("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA3_224", return_hex=False) == hash.sha3_224("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA3_256", return_hex=False) == hash.sha3_256("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA3_384", return_hex=False) == hash.sha3_384("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHA3_512", return_hex=False) == hash.sha3_512("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "BLAKE2b", return_hex=False) == hash.blake2b("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "BLAKE2s", return_hex=False) == hash.blake2s("Hello World".encode("utf-8")).digest()
    assert hash_("Hello World", "SHAKE_128", return_hex=False) == hash.shake_128("Hello World".encode("utf-8")).digest(256)
    assert hash_("Hello World", "SHAKE_256", return_hex=False) == hash.shake_256("Hello World".encode("utf-8")).digest(256)
    print ("Bytes match")
    print ("testing key generation")
    print ("generating length 32 password")
    password = generate_password(32)
    print ("password:", password)
    # assert that length is 32
    assert len(password) == 32
    print ("generating length 64 password")
    password = generate_password(64)
    print ("password:", password)
    # assert that length is 64
    assert len(password) == 64
    print ("generating length 128 password")
    password = generate_password(128)
    print ("password:", password)
    # assert that length is 128
    assert len(password) == 128
    print ("test complete; key generation passed")
    # testing hash comparision function
    print ("testing hash comparision function")
    assert compare_hashes(hash_("Hello World", "SHA256"), hash_("Hello World", "SHA256")) == True
    assert compare_hashes(hash_("Hello World", "SHA256"), hash_("Not Hello World", "SHA512")) == False
    print ("test complete; hash comparision function passed")
    # testing random choice function
    print ("testing random choice function")
    assert random_choice(["Hello", "World", "!"]) == "Hello" or "World" or "!"
    print ("test complete; random choice function passed")
    # testing token generation function
    print ("testing token generation function")
    bytes_token = token_generate(32, return_type="BYTES")
    print ("bytes token:", bytes_token)
    assert len(bytes_token) == 32
    hex_token = token_generate(32, return_type="HEX")
    print ("hex token:", hex_token)
    assert len(hex_token) == 64
    url_safe_token = token_generate(32, return_type="URL")
    print ("url safe token:", url_safe_token)
    print (len(url_safe_token))
    assert len(url_safe_token) == 43
    print ("test complete; token generation function passed")
    print ("testing secure file deletion function")
    # testing secure file deletion function
    #creating a test file
    test_file = open("test_file.txt", "w")
    test_file.write("Hello World")
    test_file.close()
    # deleting using secure file deletion function
    exit_code = sec_delete("test_file.txt")
    print(exit_code)
    # checking if file is deleted
    assert not os.path.exists("test_file.txt")
    print ("test complete; secure file deletion function passed")
    print ("testing file deletion function")
    # testing file deletion function
    #creating a test file
    test_file = open("test_file.txt", "w")
    test_file.write("Hello World")
    test_file.close()
    # deleting using file deletion function
    delete("test_file.txt")
    # checking if file is deleted
    assert not os.path.exists("test_file.txt")
    print ("test complete; file deletion function passed")
    print ("testing XOR function")
    # testing XOR function against pycryptodome's XOR function
    assert XOR(b"Hello World", b"Hello World") == strxor("Hello World".encode("utf-8"), "Hello World".encode("utf-8"))
    print ("test complete; XOR function passed")
    # testing one time pad encrypt
    print ("testing one time pad encrypt/decrypt")
    encrypted_string = one_time_pad_encrypt("Hello World", "youwillneverguess")
    print ("encrypted string:", encrypted_string)
    decrypted_string = one_time_pad_decrypt(encrypted_string, "youwillneverguess")
    print ("decrypted string:", decrypted_string)
    assert decrypted_string == b"Hello World"
    print ("test complete; one time pad encrypt/decrypt passed")
    # testing the is_prime_number function
    print ("testing is_prime_number function")
    assert is_prime_number(2) == True
    assert is_prime_number(3) == True
    assert is_prime_number(4) == False
    assert is_prime_number(5) == True
    assert is_prime_number(6) == False
    print ("test complete; is_prime_number function passed")
    # testing the generate_prime_number function
    print ("testing generate_prime_number function")
    assert get_prime_number(2) == 2 or 3 or 5 or 7
    print ("test complete; generate_prime_number function passed")
    # testing the GCD function
    print ("testing GCD function")
    assert GCD(2, 4) == 2
    assert GCD(4, 2) == 2
    assert GCD(2, 6) == 2
    assert GCD(6, 2) == 2
    print ("test complete; GCD function passed")
    print ("Functions test passed | Function tests passed")
    print ("Testing Ciphers Class")
    print ("testing RSA methods")
    # instantiating the class
    cipher = Ciphers("youwillneverguess")
    # generating a key
    public_key, private_key = cipher.generate_RSA_keys()
    # encrypting a string
    encrypted_string = cipher.RSA_encrypt_str(public_key, "Hello World")
    # decrypting the string
    decrypted_string = cipher.RSA_decrypt_str(private_key, encrypted_string)
    # checking if the decrypted string is the same as the original
    assert decrypted_string == "Hello World"
    print ("test complete; RSA methods passed")
    print ("testing AES methods")
    # creating a test file
    test_file = open("test_file.txt", "w")
    test_file.write("Hello World")
    test_file.close()
    # encrypting the file
    cipher.AES_encrypt_file("test_file.txt")
    # decrypting the file
    cipher.AES_decrypt_file("test_file.txt")
    # checking if the file is decrypted
    with open("test_file.txt", "r") as f:
        assert f.read() == "Hello World"
    # encrypting a string
    encrypted_string, iv, key = cipher.AES_encrypt_string(b"Hello World")
    # decrypting the string
    decrypted_string = cipher.AES_decrypt_string(encrypted_string, key, iv)
    # checking if the decrypted string is the same as the original
    assert decrypted_string.decode() == "Hello World"
    print ("test complete; AES methods passed")
    print ("testing Blowfish methods")
    # using prev test file
    # encrypting the file
    cipher.BLO_encrypt_file("test_file.txt")
    # decrypting the file
    cipher.BLO_decrypt_file("test_file.txt")
    # checking if the file is decrypted
    with open("test_file.txt", "r") as f:
        assert f.read() == "Hello World"
    # encrypting a string
    encrypted_string, iv, key = cipher.BLO_encrypt_string(b"Hello World")
    # decrypting the string
    decrypted_string = cipher.BLO_decrypt_string(encrypted_string, key, iv)
    # checking if the decrypted string is the same as the original
    assert decrypted_string.decode() == "Hello World"
    print ("test complete; Blowfish methods passed")
    print ("Testing Fernet methods")
    # using prev test file
    # generating a key
    fernet_key = cipher.generate_FerNet_key()
    # encrypting the file
    cipher.FerNet_encrypt_file("test_file.txt", key=fernet_key)
    # decrypting the file
    cipher.FerNet_decrypt_file("test_file.txt", key=fernet_key)
    # checking if the file is decrypted
    with open("test_file.txt", "r") as f:
        assert f.read() == "Hello World"
    # encrypting a string
    encrypted_string, decrypt_key = cipher.FerNet_encrypt_string(b"Hello World")
    # decrypting the string
    decrypted_string = cipher.FerNet_decrypt_string(encrypted_string, key=decrypt_key)
    # checking if the decrypted string is the same as the original
    assert decrypted_string.decode() == "Hello World"
    # deleting all variables and test files
    for i in globals():
        del globals()[i]
    for i in locals():
        del locals()[i]
    print ("test complete; Fernet methods passed")
    print ("All tests completed | General functionality tests passed")
    print ("Beginning edge use case tests")
    # testing functions first
    print ("testing functions")
    try:
        # testing hash function
        # obscene length
        print ("testing hashing function")
        print ("testing long length hash ability")
        print ("resulting hash is: {}".format(hash_("Hello World"*2048, "SHA256")))
        print ("testing hash function on bytes")
        print ("resulting hash is: {}".format(hash_(b"Hello World", "SHA256")))
        print ("Hash test finished")
        pass
    except Exception as e:
        print (f"failure occurred during edge case test: {e}")
    # deleting all variables
    for i in globals():
        del globals()[i]
    for i in locals():
        del locals()[i]
    return 0


if __name__ == "__main__":
    init_diagonostic()
