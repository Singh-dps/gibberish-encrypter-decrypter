import getpass
import hashlib
import secrets
import sys

CONSONANTS = "bcdfghjklmnpqrstvwxz"
VOWELS = "aeiou"


def generate_syllables():
    """Generates 256 unique CVC syllables."""
    syllables = []
    # We need 256.
    # 20 consonants * 5 vowels * 20 consonants = 2000 combinations.
    # We'll just take the first 256.
    for c1 in CONSONANTS:
        for v in VOWELS:
            for c2 in CONSONANTS:
                syllables.append(c1 + v + c2)
                if len(syllables) == 256:
                    return syllables
    return syllables


SYLLABLES = generate_syllables()
SYLLABLE_TO_BYTE = {s: i for i, s in enumerate(SYLLABLES)}


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from the password and salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)


def get_keystream(key: bytes, length: int) -> bytes:
    """Generates a keystream of `length` bytes using the key."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(16, "big")
        block = hashlib.sha256(key + counter_bytes).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])


def encode_bytes_to_gibberish(data: bytes) -> str:
    """Encodes bytes to a string of CVC syllables."""
    return "".join(SYLLABLES[b] for b in data)


def decode_gibberish_to_bytes(text: str) -> bytes:
    """Decodes a string of CVC syllables back to bytes."""
    # Since every syllable is exactly 3 chars, this is easy and robust.
    if len(text) % 3 != 0:
        raise ValueError("Invalid gibberish length (must be multiple of 3)")

    data = bytearray()
    for i in range(0, len(text), 3):
        chunk = text[i : i + 3]
        if chunk not in SYLLABLE_TO_BYTE:
            raise ValueError(f"Invalid syllable: {chunk}")
        data.append(SYLLABLE_TO_BYTE[chunk])
    return bytes(data)


def encrypt(text: str, password: str) -> str:
    """Encrypts text into gibberish."""
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)

    text_bytes = text.encode("utf-8")
    keystream = get_keystream(key, len(text_bytes))

    encrypted_bytes = bytes(a ^ b for a, b in zip(text_bytes, keystream))

    # Prepend salt
    full_payload = salt + encrypted_bytes

    return encode_bytes_to_gibberish(full_payload)


def decrypt(gibberish: str, password: str) -> str:
    """Decrypts gibberish back to text."""
    try:
        full_payload = decode_gibberish_to_bytes(gibberish)
    except ValueError as e:
        return f"Error: Corrupted or invalid gibberish. ({e})"

    if len(full_payload) < 16:
        return "Error: Message too short."

    salt = full_payload[:16]
    encrypted_bytes = full_payload[16:]

    key = derive_key(password, salt)
    keystream = get_keystream(key, len(encrypted_bytes))

    decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, keystream))

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return "Error: Decryption failed (wrong password?)"


def main():
    print("--- Gibberish Encryptor (CVC Edition) ---")
    mode = input("Mode (encrypt/decrypt): ").strip().lower()
    if not mode:
        print("Exiting.")
        return

    if mode.startswith("e"):
        text = input("Enter text to encrypt: ")
        if not text:
            print("No text provided. Exiting.")
            return

        password = getpass.getpass("Enter password (default: 123): ")
        if not password:
            password = "123"
        result = encrypt(text, password)
        print(f"\nEncrypted Gibberish:\n{result}")
    elif mode.startswith("d"):
        gibberish = input("Enter gibberish to decrypt: ")
        if not gibberish:
            print("No gibberish provided. Exiting.")
            return

        password = getpass.getpass("Enter password (default: 123): ")
        if not password:
            password = "123"
        result = decrypt(gibberish, password)
        print(f"\nDecrypted Text:\n{result}")
    else:
        print("Invalid mode.")


if __name__ == "__main__":
    main()
