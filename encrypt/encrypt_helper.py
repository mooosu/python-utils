from Crypto.Cipher import DES
from Crypto.Cipher import DES3
import base64
from pkcs7 import PKCS7Encoder
class EncryptHelper(object):
    @staticmethod
    def des3_encrypt_ecb_pkcs7(text,key,mod_k = 8):
        d3= DES3.new(key, DES.MODE_ECB)
        encoder = PKCS7Encoder(mod_k)
        pad_text = encoder.encode(text)
        return base64.b64encode(d3.encrypt(pad_text)).encode("hex")

    @staticmethod
    def des3_decrypt_ecb_pkcs7(text,key,mod_k = 8):
        des3_text = base64.b64decode(text.decode("hex"))
        d3= DES3.new(key, DES.MODE_ECB)
        pad_text = d3.decrypt(des3_text)
        decoder = PKCS7Encoder(mod_k)
        text = decoder.decode(pad_text)
        return text

if __name__ == "__main__":
    text = "hello"
    e = EncryptHelper.des3_encrypt_ecb_pkcs7("hello","1231231212312312")
    d = EncryptHelper.des3_decrypt_ecb_pkcs7(e,"1231231212312312")
    assert(d == text )
