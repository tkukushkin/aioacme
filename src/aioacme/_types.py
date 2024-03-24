from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

PrivateKeyTypes = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
