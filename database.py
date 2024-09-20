import bcrypt
import datetime
import sqlite3
import random
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import AES


def encrypt_data(data, key='1Yg9w1fYwD5RprcVg/kSWyOrHqKIpTmY', iv='s9ch6K3zm6/FpWyI'):
    if data is None:
        return None
    block_size = AES.block_size
    encryption_key = key.encode('utf-8')
    encryption_vector = iv.encode('utf-8')

    cipher = AES.new(encryption_key, AES.MODE_CBC, encryption_vector)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), block_size))
    
    return b64encode(ciphertext).decode('utf-8')


def decrypt_data(data, key='1Yg9w1fYwD5RprcVg/kSWyOrHqKIpTmY', iv='s9ch6K3zm6/FpWyI'):
    if data is None:
        return None
    block_size = AES.block_size
    encryption_key = key.encode('utf-8')
    encryption_vector = iv.encode('utf-8')

    cipher_text = b64decode(data)
    cipher = AES.new(encryption_key, AES.MODE_CBC, encryption_vector)
    decrypted_value = unpad(cipher.decrypt(cipher_text), block_size).decode('utf-8')

    return decrypted_value


def generate_encryption_key_iv(key_length=32, iv_length=16):
    key = get_random_bytes(key_length)
    iv = get_random_bytes(iv_length)

    encryption_key = b64encode(key).decode('utf-8')[:key_length]
    encryption_iv = b64encode(iv).decode('utf-8')[:iv_length]

    print({'key': encryption_key, 'iv': encryption_iv})
    return {'key': encryption_key, 'iv': encryption_iv}


def init_db():
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        role TEXT,
                        first_name TEXT,
                        last_name TEXT,
                        age INTEGER,
                        gender TEXT,
                        weight REAL,
                        address TEXT,
                        zip_code TEXT,
                        city TEXT,
                        email TEXT,
                        phone TEXT,
                        registration_date TEXT,
                        member_id TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      log_entry TEXT)''')

    conn.commit()
    conn.close()

    print("Database initialized.")
    print('\n')


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def log_activity(username, description, additional_info='', suspicious=False):
    log_entry = f"{datetime.datetime.now()}|{username}|{description}|{additional_info}|{'Yes' if suspicious else 'No'}"
    encrypted_log_entry = encrypt_data(log_entry)

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO logs (log_entry) VALUES (?)''', (encrypted_log_entry,))
    conn.commit()
    conn.close()



def generate_member_id():
    current_year = datetime.datetime.now().year
    year_suffix = str(current_year)[-2:]

    unique_id_body = year_suffix + ''.join([str(random.randint(0, 9)) for _ in range(7)])
    checksum = sum(int(digit) for digit in unique_id_body) % 10
    member_id = unique_id_body + str(checksum)

    return member_id


def add_user(username, password, role, first_name, last_name, zip_code=None, age=None, gender=None, weight=None,
             address=None, city=None, email=None, phone=None, is_new=False):
    try:
        hashed_password = hash_password(password)
        reg_date = datetime.datetime.now().strftime("%Y-%m-%d")
        member_id = generate_member_id() if role == 'member' and is_new else None

        conn = sqlite3.connect('unique_meal.db')
        cursor = conn.cursor()

        # Encrypt data before saving to the database
        encrypted_first_name = encrypt_data(first_name)
        encrypted_last_name = encrypt_data(last_name)
        encrypted_age = encrypt_data(str(age)) if age is not None else None
        encrypted_gender = encrypt_data(gender)
        encrypted_weight = encrypt_data(str(weight)) if weight is not None else None
        encrypted_address = encrypt_data(address)
        encrypted_zip_code = encrypt_data(zip_code)
        encrypted_city = encrypt_data(city)
        encrypted_email = encrypt_data(email)
        encrypted_phone = encrypt_data(phone)
        encrypted_role = encrypt_data(role)
        encrypted_username = encrypt_data(username)
        encrypted_registration_date = encrypt_data(reg_date)
        encrypted_member_id = encrypt_data(member_id)

        cursor.execute('''INSERT INTO users (username, password, role, first_name, last_name, age, gender, weight, address, zip_code, city, email, phone, registration_date, member_id)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (encrypted_username, hashed_password, encrypted_role, encrypted_first_name, encrypted_last_name, encrypted_age,
                        encrypted_gender, encrypted_weight, encrypted_address, encrypted_zip_code, encrypted_city,
                        encrypted_email, encrypted_phone, encrypted_registration_date, encrypted_member_id))

        print('User addition query executed.')
        conn.commit()
        print('Database commit successful.')
        log_activity(username, "User added successfully")
    except sqlite3.IntegrityError as e:
        log_activity(username, "Failed to add user", str(e), suspicious=True)
        print(f"IntegrityError: {e}")
    except Exception as e:
        log_activity(username, "Unexpected error", str(e), suspicious=True)
        print(f"Exception: {e}")
    finally:
        conn.close()
        print('Database connection closed.')


def add_super_admin():
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    # Encrypt the username for checking its existence
    encrypted_username = encrypt_data("super_admin")
    #print('on create', encrypted_username)
    #print('\n')

    cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
    if cursor.fetchone() is None:
        hashed_pw = hash_password("Admin_123?")
        reg_date = "2023-01-01"

        # Encrypt the rest of the data
        encrypted_first_name = encrypt_data("Super")
        encrypted_last_name = encrypt_data("Admin")
        encrypted_reg_date = encrypt_data(reg_date)
        encrypted_role = encrypt_data("super_admin")

        try:
            cursor.execute('''INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (encrypted_username, hashed_pw, encrypted_role, encrypted_first_name, encrypted_last_name,
                            encrypted_reg_date))
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)

        print("Super admin added successfully.")
        print('\n')

    else:
        print("Super admin already exists.")
        print('\n')

    conn.close()
    print('Database connection closed after adding super admin if not already present.')
    print('\n')

def modify_user_information(username, first_name=None, last_name=None, age=None, gender=None, weight=None, address=None,
                            city=None, zip_code=None, email=None, phone=None):
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()
    encrypted_username = encrypt_data(username)

    cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
    member = cursor.fetchone()

    if member:
        # Decrypt existing data to use in case new values are not provided
        existing_data = {
            'first_name': decrypt_data(member[4]),
            'last_name': decrypt_data(member[5]),
            'age': decrypt_data(member[6]),
            'gender': decrypt_data(member[7]),
            'weight': decrypt_data(member[8]),
            'address': decrypt_data(member[9]),
            'city': decrypt_data(member[10]),
            'zip_code': decrypt_data(member[11]),
            'email': decrypt_data(member[12]),
            'phone': decrypt_data(member[13]),
        }

        updates = {
            'first_name': encrypt_data(first_name or existing_data['first_name']),
            'last_name': encrypt_data(last_name or existing_data['last_name']),
            'age': encrypt_data(str(age) if age is not None else existing_data['age']),
            'gender': encrypt_data(gender or existing_data['gender']),
            'weight': encrypt_data(str(weight) if weight is not None else existing_data['weight']),
            'address': encrypt_data(address or existing_data['address']),
            'city': encrypt_data(city or existing_data['city']),
            'zip_code': encrypt_data(zip_code or existing_data['zip_code']),
            'email': encrypt_data(email or existing_data['email']),
            'phone': encrypt_data(phone or existing_data['phone']),
        }

        cursor.execute('''UPDATE users 
                          SET first_name=?, last_name=?, age=?, gender=?, weight=?, address=?, city=?, zip_code=?, email=?, phone=? 
                          WHERE username=?''',
                       (updates['first_name'], updates['last_name'], updates['age'], updates['gender'],
                        updates['weight'], updates['address'], updates['city'], updates['zip_code'], updates['email'], updates['phone'],
                        encrypted_username))

        conn.commit()
        log_activity('consultant', 'Modified user information', f'username: {username}')
       
        print("User information updated successfully!")
        print('\n')

    else:
        print("User not found.")

    conn.close()



def search_user(search_key , role):
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    print(f"Searching for members with key: {search_key}")

    try:
        cursor.execute(" SELECT * FROM users where role = ?", (role,))
        results = cursor.fetchall()

        decrypted_results = []
        if results:
            for member in results:
                decrypted_member = {
                    'ID': member[0],
                    'Username': decrypt_data(member[1]),
                    'First Name': decrypt_data(member[4]),
                    'Last Name': decrypt_data(member[5]),
                    'Age': member[6],
                    'Gender': decrypt_data(member[7]),
                    'Weight': member[8],
                    'Address': decrypt_data(member[9]),
                    'Zip code': decrypt_data(member[10]),
                    'City': decrypt_data(member[11]),
                    'Email': decrypt_data(member[12]),
                    'Phone': decrypt_data(member[13]),
                    'Registration Date': decrypt_data(member[14]),
                    'Role': decrypt_data(member[3])
                }

                if any(search_key.lower() in str(decrypted_member[field]).lower() for field in decrypted_member if decrypted_member[field]):
                    decrypted_results.append(decrypted_member)
                    (f"ID: {decrypted_member['ID']}, Username: {decrypted_member['Username']}, Name: {decrypted_member['First Name']} {decrypted_member['Last Name']}, Age: {decrypted_member['Age']}, Gender: {decrypted_member['Gender']}, Weight: {decrypted_member['Weight']}")
                    (f"Address: {decrypted_member['Address']}, Zip code: {decrypted_member['Zip code']}, City: {decrypted_member['City']}, Email: {decrypted_member['Email']}")
                    (f"Registration Date: {decrypted_member['Registration Date']}, Role: {decrypted_member['Role']}\n")
        else:
            print("No members found.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()
    return decrypted_results


def display_users():
    try:
        conn = sqlite3.connect('unique_meal.db')
        cursor = conn.cursor()

        print("Displaying all users")
        print('\n')

        query = 'SELECT * FROM users'
        cursor.execute(query)
        results = cursor.fetchall()
   
        print(f"Number of users found: {len(results)}")
        print('\n')

        decrypted_results = []
        if results:
            for user in results:
                decrypted_user = {
                    'Username': decrypt_data(user[1]),
                    'Role': decrypt_data(user[3]),
                    'member_id': decrypt_data(user[15])
                }
                decrypted_results.append(decrypted_user)

            print('\n')
        else:
            print("No users found.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

    return decrypted_results

def read_logs():
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()
    cursor.execute("SELECT log_entry FROM logs")
    logs = cursor.fetchall()
    conn.close()
    return logs


if __name__ == "__main__":
    init_db()
    add_super_admin()
