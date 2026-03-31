from cryptography.fernet import Fernet
import hashlib
import os

# ==============================
# KEY GENERATION
# ==============================

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)
    print("🔑 Key generated and saved!")

# ==============================
# LOAD KEY
# ==============================

def load_key():
    return open("secret.key", "rb").read()

# ==============================
# HASH (INTEGRITY CHECK)
# ==============================

def generate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()

# ==============================
# ENCRYPT FILE
# ==============================

def encrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    with open(file_path + ".enc", "wb") as enc_file:
        enc_file.write(encrypted)

    # Save hash
    file_hash = generate_hash(file_path)
    with open(file_path + ".hash", "w") as h:
        h.write(file_hash)

    print("🔒 File encrypted successfully!")
    print("📁 Encrypted file:", file_path + ".enc")

# ==============================
# DECRYPT FILE
# ==============================

def decrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    output_file = file_path.replace(".enc", "_decrypted.txt")

    with open(output_file, "wb") as dec_file:
        dec_file.write(decrypted)

    # Verify integrity
    original_hash_file = file_path.replace(".enc", ".hash")

    if os.path.exists(original_hash_file):
        with open(original_hash_file, "r") as h:
            original_hash = h.read()

        new_hash = generate_hash(output_file)

        if original_hash == new_hash:
            print("✅ Integrity Verified (No tampering)")
        else:
            print("❌ Integrity FAILED (File modified!)")

    print("🔓 File decrypted:", output_file)

# ==============================
# MAIN MENU
# ==============================

def main():
    print("\n🔐 Secure File Transfer Module")

    print("1. Generate Key")
    print("2. Encrypt File")
    print("3. Decrypt File")

    choice = input("Enter choice: ")

    if choice == "1":
        generate_key()

    elif choice == "2":
        file_path = input("Enter file path: ")
        encrypt_file(file_path)

    elif choice == "3":
        file_path = input("Enter encrypted file (.enc): ")
        decrypt_file(file_path)

    else:
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()