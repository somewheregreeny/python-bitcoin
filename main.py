from ecc import PrivateKey
from helper import hash256, little_endian_to_int

secret = little_endian_to_int(hash256(b''))
private_key = PrivateKey(secret)
print(private_key.point.address(testnet=True))
print(private_key.wif())