from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as Sig_pk
from Crypto.PublicKey import RSA
import base64
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

#
# msg = "'userId':'6974','searchWord':'陈','beginDateTime':'2020-09-14','endDateTime':'2020-09-17','curPage':1,'perPage':3"
msg="'userId':'39369','searchWord':'田','beginDateTime':'2021-07-13','endDateTime':'2021-07-13','curPage':1,'perPage':3"
#
# 读取文件中的公钥
key = open('pubkey.pem').read()
publickey = RSA.importKey(key)
# 进行加密
pk = PKCS1_v1_5.new(publickey)
encrypt_text = pk.encrypt(msg.encode())
# print(encrypt_text)
# 加密通过base64进行编码
result = base64.b64encode(encrypt_text)
print(result)

# # 密文key

# base64解码
result= base64.b64decode(result)
# 获取私钥
privatekey = open('privkey.pem').read()
rsakey = RSA.importKey(privatekey)
# 进行解密
cipher = PKCS1_v1_5.new(rsakey)
text = cipher.decrypt(result, 'DecryptError')
# 解密出来的是字节码格式，decodee转换为字符串
print(text.decode())

# 待签名内容
# name = "'userId':'6974','searchWord':'陈','beginDateTime':'2020-09-14','endDateTime':'2020-09-17','curPage':1,'perPage':3"
# 获取私钥
key = open('privkey.pem', 'r').read()
rsakey = RSA.importKey(key)
# 根据sha算法处理签名内容  (此处的hash算法不一定是sha,看开发)
data = SHA.new(msg.encode())
# 私钥进行签名
sig_pk = Sig_pk.new(rsakey)
sign = sig_pk.sign(data)
# 将签名后的内容，转换为base64编码
result = base64.b64encode(sign)
# 签名结果转换成字符串
print(result)
data = result.decode()
print(data)
# name = "musen"
# data="DFy/50f6TyOQqx6c/Eqe/AzmIpQ2Nzwdw0b1TPfblglmqUNzmTS00UDeSFSdA9mXpXW2JdpNjAXYgBsPEDsKRUpX/sLraaSf8HpmdPOCoO8LgDBUkcj5Xa92n3et57rlPJhb2CkTm/w8cw0NPV9lK9Xb/GklcrPaw8H50G2usd3x0qkriz11jYH7+L6TMr6PccVwrZ1qmATO2iiZrxRG7j663athca4ZZZkph9dqlIREfwFEMY2mupyhffUW/gUw1wrRxaHBPKe5ZLLBQa/frJHdCAgDBDRkuZHYBbAsBGHd1aQw1p3yaUyUBlmGioqTZ1Hqv2/utHcKfFvRX2m5Ag=="
# 签名数据
# data="BkbQC9YkbaPbyOEAIvQSAo0b9K9LxDD/mjpfsrkLnwBvieQBsS1Vns3Oumi4GrWDKpOykMA2aUN/mVXUGIJ8mQs39AnwHQUiOXKUS6aNZeUQROLw306JprWPNmlsjz2X9mgCq1cXFzV6Mmy9hPDS4xZ2pu9aGTuM8/3nQz7mDtSXZbuiCMlmgH5qV4eZnInUkE1Ac/pFv3MbUA8PjAzeClPjZww3jzBfDFGLHO4rEcxT2OfEZsprj2zrUoSGgpd0WFkBuagTvmAke9dka03sfwXFnhjZjRYkTdtTBULGLwM4sUw5ATCHPNVirZhpANZmsDiKs6tgN5AXlnB1JGPZKg=="
# data="X3Gg+wd7UDh4X8ra+PGCyZFUrG+6jDeQt6ajMA0EjwoDwxlddLzYoS4dtjQ2q5WCcRhxcp8fjEyoPXBmJE9rMKDjEIeE/VO0sskbJiO65fU8hgcqdWdgbVqRryhOw+Kih+I6RIeNRYnOB8GkGD8Qca+n9JlOELcxLRdLo3vx6dw="
# base64解码
data = base64.b64decode(data)
# 获取公钥
key = open('pubkey.pem').read()
rsakey = RSA.importKey(key)
# 将签名之前的内容进行hash处理
sha_name = SHA.new(msg.encode())
# 验证签名
signer = Sig_pk.new(rsakey)
result = signer.verify(sha_name, data)
# 验证通过返回True   不通过返回False
print(result)
