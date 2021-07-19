# -*- coding:utf-8 -*-
from base64 import b64encode, decodebytes, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipper
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign
from Crypto.Hash import SHA1, SHA256

from core.core import app


class Rsa:
    """RSA加解密签名类
    """

    def __init__(self, ciper_lib=PKCS1_v1_5_cipper, sign_lib=PKCS1_v1_5_sign, hash_lib_256=SHA256, hash_lib=SHA1,
                 pub_file=app.config["PUBLIC_KEY_FILEPATH"], pri_file=app.config["PRIVATE_KEY_FILEPATH"],
                 reversed_size=11):
        # 加解密库
        self.ciper_lib = ciper_lib
        self.sign_lib = sign_lib
        self.hash_lib = hash_lib
        self.hash_lib_256 = hash_lib_256
        self.pub_key = RSA.importKey(open(pub_file).read()) if pub_file else None
        self.pri_key = RSA.importKey(open(pri_file).read()) if pri_file else None

        # 分块保留长度
        self.block_reversed_size = reversed_size

    # 根据key长度计算分块大小
    def get_block_size(self, rsa_key):
        try:
            # RSA仅支持限定长度内的数据的加解密，需要分块
            # 分块大小
            reserve_size = self.block_reversed_size
            key_size = rsa_key.size_in_bits()
            if (key_size % 8) != 0:
                raise RuntimeError('RSA 密钥长度非法')

            # 密钥用来解密，解密不需要预留长度
            if rsa_key.has_private():
                reserve_size = 0

            bs = int(key_size / 8) - reserve_size
        except Exception as err:
            print('计算加解密数据块大小出错', rsa_key, err)
        return bs

    # 返回块数据
    def block_data(self, data, rsa_key):
        bs = self.get_block_size(rsa_key)
        for i in range(0, len(data), bs):
            yield data[i:i + bs]

    # 加密
    def enc_bytes(self, data, key=None):
        text = b''
        data = data.encode()
        try:
            rsa_key = self.pub_key
            if key:
                rsa_key = key

            cipher = self.ciper_lib.new(rsa_key)
            for dat in self.block_data(data, rsa_key):
                cur_text = cipher.encrypt(dat)
                text += cur_text
        except Exception as err:
            print('RSA加密失败', data, err)
        return b64encode(text).decode()

    # 解密
    def dec_bytes(self, data, key=None):
        text = b''
        try:
            rsa_key = self.pri_key
            if key:
                rsa_key = key

            cipher = self.ciper_lib.new(rsa_key)
            data = decodebytes(data.encode())

            for dat in self.block_data(data, rsa_key):
                cur_text = cipher.decrypt(dat, '解密异常')
                text += cur_text
        except Exception as err:
            print('RSA解密失败', data, err)
        return text.decode()

    # RSA签名
    def sign_bytes(self, data, key=None):
        signature = ''
        try:
            rsa_key = self.pri_key
            if key:
                rsa_key = key

            h = self.hash_lib.new(data)
            signature = self.sign_lib.new(rsa_key).sign(h)
        except Exception as err:
            print('RSA签名失败', '', err)
        return b64encode(signature).decode()

    # RSA签名256
    def sign_bytes_SHA256(self, data, key=None):
        signature = ''
        try:
            rsa_key = self.pri_key
            if key:
                rsa_key = key

            h = self.hash_lib_256.new(data)
            signature = self.sign_lib.new(rsa_key).sign(h)
        except Exception as err:
            print('RSA签名失败', '', err)
        return b64encode(signature).decode()

    # RSA签名验证
    def sign_verify(self, data, sig, key=None):
        sig = b64decode(sig.encode())
        rsa_key = self.pub_key
        if key:
            rsa_key = key
        h = self.hash_lib.new(data)
        return self.sign_lib.new(rsa_key).verify(h, sig)

    # RSA签名验证256
    def sign_verify_SHA256(self, data, sig, key=None):
        sig = b64decode(sig)
        rsa_key = self.pub_key
        if key:
            rsa_key = key
        h = self.hash_lib_256.new()
        h.update(data)
        return self.sign_lib.new(rsa_key).verify(h, sig)


if __name__ == '__main__':

    # rsa = Rsa(pub_file="F:/wbw/code/ining/public.pem",
    #           pri_file="F:/wbw/code/ining/privkey.pem")
    import json
    #
    # encryptedData = {
    #     "customer_name": "陈怡海",
    #     "customer_phone": "18117321018",
    #     "customer_id_card": "310109198210181535",
    #     "customer_bank_card": "6217560800023362683",
    # }
    # encryptedData = rsa.enc_bytes(data=json.dumps(encryptedData))  # 加密 type:b64
    # print(encryptedData)
    # print("\n")
    # sign = rsa.sign_bytes(data=encryptedData.encode())
    # print(sign)
# -*- coding:utf-8 -*-