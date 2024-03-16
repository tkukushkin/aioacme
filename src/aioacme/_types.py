from cryptography.hazmat.primitives.asymmetric import ec, rsa

PrivateKeyTypes = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
