"""Usage: python3 decrypt_mremoteng.py <base64-encoded encrypted password> <optional passphrase>"""

import sys
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def derive_key(
        passphrase,
        salt,
        hash_type="sha1",
        key_length=32,
        num_iterations=1000,
    ):
    """Use PBDKF2 to generate the key.
    By default, use 32 bytes for the key, 1000 iterations, and SHA-1 as the
    hash function.
    """

    return hashlib.pbkdf2_hmac(
        hash_type,
        passphrase.encode(),
        salt,
        num_iterations,
        dklen=key_length,
    )

def decrypt_password(key, associated_data, iv, ciphertext, tag):
    """Decrypt the provided ciphertext using AES-256-GCM using the provided key,
    associated data, initialization vector, and GCM tag."""

    password_decryptor = Cipher(
        algorithms.AES(key), # Use AES
        modes.GCM(iv, tag), # Use GCM mode.
        backend=default_backend()
    ).decryptor()

    # Use the associated data.
    password_decryptor.authenticate_additional_data(associated_data)

    # Decrypt and finalize.
    return password_decryptor.update(ciphertext) + password_decryptor.finalize()

def main(argv):
    """Main function. Take in the base64 string for the ciphertext, extract
    the encryption information, and decrypt the ciphertext."""

    ciphertext = base64.b64decode(argv[1])
    passphrase = "mR3m" # Default mRemoteNG passphrase.

    if len(argv) > 2:
        passphrase = argv[2]

    # First 16 bytes of the ciphertext are used as the key-derivation function
    # salt, AND as the GCM associated data.
    kdf_salt = gcm_assoc_data = ciphertext[:16]

    # Next 16 bytes make up the initialization vector.
    gcm_iv = ciphertext[16:32]

    # Last 16 bytes make up the GCM auth tag. The remainder in the middle
    # is the actual encrypted password.
    encrypted_password = ciphertext[32:-16]
    gcm_auth_tag = ciphertext[-16:]

    # Generate encryption key.
    aes_key = derive_key(passphrase, kdf_salt)

    # Decrypt password.

    plaintext = decrypt_password(
        aes_key,
        gcm_assoc_data,
        gcm_iv,
        encrypted_password,
        gcm_auth_tag,
    )

    print("Password: {}".format(plaintext.decode("utf-8")))

main(sys.argv)
