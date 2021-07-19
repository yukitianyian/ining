import rsa

f, e = rsa.newkeys(2048)  # 生成公钥、私钥

e = e.save_pkcs1()  # 保存为 .pem 格式
with open("e.pem", "wb") as x:  # 保存私钥
    x.write(e)
f = f.save_pkcs1()  # 保存为 .pem 格式
with open("f.pem", "wb") as x:  # 保存公钥
    x.write(f)
with open('e.pem', mode='rb') as privatefile:
	keydata = privatefile.read()
privkey = rsa.PrivateKey.load_pkcs1(keydata)

with open('f.pem', mode='rb') as privatefile:
	keydata = privatefile.read()
pubkey = rsa.PrivateKey.load_pkcs1(keydata)
message='userId'.encode('utf8')
# 加密数据
crypto = rsa.encrypt(message, pubkey)

# 解密数据
message = rsa.decrypt(crypto, privkey)