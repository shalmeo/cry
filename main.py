from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes

rsa_key = RSA.generate(2048)


def encrypt_text(text: str, public_key: RsaKey) -> bytes:
    aes_key = get_random_bytes(16)

    aes_cipher = AES.new(aes_key, AES.MODE_CTR)
    rsa_cipher = PKCS1_OAEP.new(public_key)

    encrypted_aes_text = aes_cipher.encrypt(text.encode())
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    return "sep".encode().join(
        [encrypted_aes_text, encrypted_aes_key, aes_cipher.nonce]
    )


def decrypt_text(encrypted_text: bytes, private_key: RsaKey) -> str:
    encrypted_aes_text, encrypted_aes_key, nonce = encrypted_text.split("sep".encode())

    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    aes_cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    text = aes_cipher.decrypt(encrypted_aes_text)

    return text.decode()


def main():
    with open("text.txt", "r") as file:
        text = file.read()

    encrypted_text = encrypt_text(text, public_key=rsa_key.publickey())
    decrypted_text = decrypt_text(encrypted_text, private_key=rsa_key)

    print(decrypted_text)


if __name__ == "__main__":
    main()
