# -*- coding:utf-8 -*-
# !-*- coding:utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Signature import PKCS1_v1_5 as pk


def sign(signdata):
    privatekey = RSA.importKey(ASNKEY)
    h = MD5.new(signdata)
    signer = pk.new(privatekey)
    signn = signer.sign(h)
    signn = ByteToHex(signn)
    return signn


def ByteToHex(bins):
    return ''.join(["%02x" % x for x in bins]).strip()


def HexToByte(hexStr):
    return bytes.fromhex(hexStr)


ASNKEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALecq3BwAI4YJZwhJ+snnDFj3lF3DMqNPorV6y5ZKXCiCMqj8OeOmxk4YZW9aaV9
ckl/zlAOI0mpB3pDT+Xlj2sCAwEAAQJAW6/aVD05qbsZHMvZuS2Aa5FpNNj0BDlf38hOtkhDzz/h
kYb+EBYLLvldhgsD0OvRNy8yhz7EjaUqLCB0juIN4QIhAOeCQp+NXxfBmfdG/S+XbRUAdv8iHBl+
F6O2wr5fA2jzAiEAywlDfGIl6acnakPrmJE0IL8qvuO3FtsHBrpkUuOnXakCIQCqdr+XvADI/UTh
TuQepuErFayJMBSAsNe3NFsw0cUxAQIgGA5n7ZPfdBi3BdM4VeJWb87WrLlkVxPqeDSbcGrCyMkC
IFSs5JyXvFTreWt7IQjDssrKDRIPmALdNjvfETwlNJyY
-----END RSA PRIVATE KEY-----"""

PCKS8KEY = """-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAt5yrcHAAjhglnCEn
6yecMWPeUXcMyo0+itXrLlkpcKIIyqPw546bGThhlb1ppX1ySX/OUA4jSakHekNP
5eWPawIDAQABAkBbr9pUPTmpuxkcy9m5LYBrkWk02PQEOV/fyE62SEPPP+GRhv4Q
Fgsu+V2GCwPQ69E3LzKHPsSNpSosIHSO4g3hAiEA54JCn41fF8GZ90b9L5dtFQB2
/yIcGX4Xo7bCvl8DaPMCIQDLCUN8YiXppydqQ+uYkTQgvyq+47cW2wcGumRS46dd
qQIhAKp2v5e8AMj9ROFO5B6m4SsVrIkwFICw17c0WzDRxTEBAiAYDmftk990GLcF
0zhV4lZvztasuWRXE+p4NJtwasLIyQIgVKzknJe8VOt5a3shCMOyysoNEg+YAt02
O98RPCU0nJg=
-----END PRIVATE KEY-----"""

header = "<!-- 537606aed546c5ba42c0820ad7fd0d74ee7caf90c232a484d0464b3332c42a9189555aebdba3570fe6566842ba7b7bb88da360f202ae9536a2a12fcdf39600c7 --><ObtainTicketResponse><message></message><prolongationPeriod>607875500</prolongationPeriod><responseCode>OK</responseCode><salt>1508484258274</salt><ticketId>1</ticketId><ticketProperties>licensee=Administrator    licenseType=0   </ticketProperties></ObtainTicketResponse>";
content = "<ObtainTicketResponse><message></message><prolongationPeriod>607875500</prolongationPeriod><responseCode>OK</responseCode><salt>1508484258274</salt><ticketId>1</ticketId><ticketProperties>licensee=Administrator\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>"
print(sign(str.encode(content)))
