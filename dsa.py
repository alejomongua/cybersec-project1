# Module for creating digital signature using DSA algorithm
# It also signs messages with SHA256 hash function
# and verifies signatures

# Generate DSA keypairs using pycryptodome
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


def generate_keypair(passphrase=None):
    """Generate DSA keypair optionally protected by passphrase"""
    # Generate keypair
    key = DSA.generate(2048)
    # Export public key
    pub_key = key.publickey().export_key(format='PEM')
    # Export private key
    priv_key = key.export_key(format='PEM', passphrase=passphrase)
    # Return tuple with keypair
    return pub_key, priv_key


def sign_message(message, priv_key, passphrase=None):
    """Sign message with private key, returns a hex encoded string"""
    if isinstance(message, str):
        message = message.encode()
    # Create key object from private key
    key = DSA.import_key(priv_key, passphrase=passphrase)
    # Calculate hash of message
    hash = SHA256.new(message)
    # Create signer object
    signer = DSS.new(key, 'fips-186-3')
    # Calculate signature
    signature = signer.sign(hash)
    # Decode signature as hex string
    signature = signature.hex()
    # Return signature
    return signature


def sign_file(filename, priv_key, passphrase=None):
    """Sign file content with private key"""
    # Open file and read its content
    with open(filename, 'rb') as f:
        file_content = f.read()

    # Sign file content
    return sign_message(file_content, priv_key, passphrase)


def verify_signature(message, signature, pub_key):
    """Verify signature from message and public key"""
    if isinstance(message, str):
        message = message.encode()
    # Create key object from public key
    key = DSA.import_key(pub_key)
    # Calculate hash of message
    hash = SHA256.new(message)
    # Create verifier object
    verifier = DSS.new(key, 'fips-186-3')
    # Decode signature from hex string
    signature = bytes.fromhex(signature)
    try:
        # Verify signature
        verifier.verify(hash, signature)
        return True
    except ValueError:
        return False


def verify_signature_file(filename, signature, pub_key):
    """Verify signature from file and public key"""
    # Open file and read its content
    with open(filename, 'rb') as f:
        file_content = f.read()

    # Verify signature
    return verify_signature(file_content, signature, pub_key)


if __name__ == '__main__':
    # Generate keypair
    pub_key, priv_key = generate_keypair()
    # print(pub_key.decode())
    # print(priv_key.decode())

    # Sign message
    message = 'The quick brown fox jumps over the lazy dog'
    signature = sign_message(message, priv_key)
    # print(signature)

    # Verify signature
    sign_ok = verify_signature(message, signature, pub_key)
    if not sign_ok:
        raise Exception('Signature is invalid. There were something wrong')

    print('Signature is valid, it is Ok')

    # Generate keypair with passphrase
    pub_key1, priv_key1 = generate_keypair(passphrase='secret')
    # print(pub_key1.decode())
    # print(priv_key1.decode())

    # Sign file
    signature = sign_file('README.md', priv_key1, passphrase='secret')
    print(signature)

    # Verify signature of file
    sign_ok = verify_signature_file('README.md', signature, pub_key1)
    if not sign_ok:
        raise Exception('Signature is invalid. There were something wrong')

    print('Signature is valid, it is Ok')

    # Sign with wrong passphrase
    try:
        sign_file('README.md', priv_key1, passphrase='secret2')
    except ValueError:
        print('Error singing with wrong passphrase. It is Ok')

    # Verify signature with wrong message
    sign_ok = verify_signature('Wrong message', signature, pub_key1)
    if sign_ok:
        raise Exception('Signature is valid. There were something wrong')

    print('Signature is invalid. It is Ok')

    # Verify signature with wrong public key
    sign_ok = verify_signature(message, signature, pub_key)
    if sign_ok:
        raise Exception('Signature is valid. There were something wrong')

    print('Signature is invalid. It is Ok')

    print('All tests passed')
