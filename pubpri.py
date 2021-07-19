import rsa
pubkey,privkey=rsa.newkeys(1024)
pub=pubkey.save_pkcs1()
pri=privkey.save_pkcs1()
with open('pu.pem',mode='wb') as f, open('pr.pem',mode='wb') as f1:
    f.write(pub)
    f1.write(pri)
with open('pu.pem',mode='rb') as f,open('pr.pem',mode='rb') as f1:
    pub=f.read()
    pri=f1.read()
    pubkey=rsa.PublicKey.load_pkcs1(pub)
    privkey=rsa.PrivateKey.load_pkcs1(pri)
message="{'userId':'6974','searchWord':'陈','beginDateTime':'2020-09-14','endDateTime':'2020-09-17','curPage':1,'perPage':3}"
info=rsa.encrypt(message.encode('utf-8'),pubkey)
msg=rsa.decrypt(info,privkey)
print(info)