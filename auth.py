import bcrypt
import sqlite3
from database import encrypt_data, decrypt_data

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))

def login():
    try:
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if not username:
            print("Username cannot be empty")
            return None
        if not password:
            print("Password cannot be empty")
            return None

        encrypted_username = encrypt_data(username)

        conn = sqlite3.connect('unique_meal.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password(user[2], password):
            decrypted_username = decrypt_data(user[1])
            print(f"Welcome {decrypted_username}!")
            return user
        else:
            print("Invalid username or password")
            return None

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return None

if __name__ == "__main__":
    user = login()
    if user:
        print("Login successful!")
        print('\n')

    else:
        print("Login failed.")
