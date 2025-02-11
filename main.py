import sys

# Reversed Password Encryption Algorithm for Deezer Mobile 

class AppContext:
    def __init__(self, name="DefaultContext"):
        self.name = name

class EncryptionHandler:
    def decrypt(self, encrypted_text):
        raise NotImplementedError

    def encrypt(self, plain_text):
        raise NotImplementedError

class ValidationUtils:
    @staticmethod
    def check_not_null(arg, arg_name):
        if arg is None:
            raise ValueError(f"{arg_name} cannot be None")
    
    @staticmethod
    def check_not_empty(result, method_name):
        if result is None:
            raise Exception(f"Result of {method_name} is None")
    
    @staticmethod
    def log_error_and_raise(message):
        sys.stderr.write(f"Error: {message}\n")
        raise Exception(message)

class EncodingUtils:
    CHARSET = "utf-8"

class ByteStringConverter:
    @staticmethod
    def bytes_to_hex(byte_data):
        return byte_data.hex()
    
    @staticmethod
    def get_encryption_key(input_obj):
        if isinstance(input_obj, AppContext): 
            return bytes([0] + [i for i in range(1, 33)])
        elif isinstance(input_obj, str):
            return input_obj.encode(EncodingUtils.CHARSET).hex()
        elif isinstance(input_obj, bytes):
            return input_obj
        else:
            raise TypeError("Unsupported type for get_encryption_key")

class SimpleEncryptor:
    def __init__(self, key):
        self.key = key

    def decrypt_data(self, encrypted_text):
        return "decrypted:" + encrypted_text

    def encrypt_data(self, plain_text):
        return "encrypted:" + plain_text

class SecureEncryption(EncryptionHandler):
    def __init__(self, context):
        ValidationUtils.check_not_null(context, "context")
        self.app_context = context
        self.encryptor = None

    def decrypt(self, encrypted_text):
        ValidationUtils.check_not_null(encrypted_text, "encrypted_text")
        key_bytes = ByteStringConverter.get_encryption_key(self.app_context)
        key = key_bytes[1:33].decode(EncodingUtils.CHARSET)
        decrypted_data = SimpleEncryptor(key).decrypt_data(encrypted_text)
        ValidationUtils.check_not_empty(decrypted_data, "decrypt")
        return decrypted_data

    def encrypt(self, plain_text):
        ValidationUtils.check_not_null(plain_text, "plain_text")
        byte_data = plain_text.encode(EncodingUtils.CHARSET)
        ValidationUtils.check_not_empty(byte_data, "encode")
        hex_representation = ByteStringConverter.bytes_to_hex(byte_data)

        if self.encryptor is not None:
            encrypted_hex = ByteStringConverter.get_encryption_key(self.encryptor.encrypt_data(hex_representation))
            ValidationUtils.check_not_empty(encrypted_hex, "string_to_hex")
            return encrypted_hex

        ValidationUtils.log_error_and_raise("EncryptionHandler not initialized")
        raise Exception("EncryptionHandler initialization error")

    def is_initialized(self):
        return self.encryptor is not None
