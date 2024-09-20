import database
import bcrypt
import sqlite3
import os
import shutil
import security
import re
import zipfile
from database import log_activity, hash_password, encrypt_data, decrypt_data

def handle_super_admin_choice(choice, user):
    if choice == '1':
        add_system_administrator(decrypt_data(user[1]))
    elif choice == '2':
        view_logs(decrypt_data(user[1]))
    elif choice == '3':
        add_consultant(decrypt_data(user[1]))
    elif choice == '4':
        modify_consultant(decrypt_data(user[1]))
    elif choice == '5':
        delete_consultant(decrypt_data(user[1]))
    elif choice == '6':
        reset_consultant_password(decrypt_data(user[1]))
    elif choice == '7':
        add_admin(decrypt_data(user[1]))
    elif choice == '8':
        modify_admin(decrypt_data(user[1]))
    elif choice == '9':
        delete_admin(decrypt_data(user[1]))
    elif choice == '10':
        reset_admin_password(decrypt_data(user[1]))
    elif choice == '11':
        backup_system(decrypt_data(user[1]))
    elif choice == '12':
        restore_system(decrypt_data(user[1]))
    elif choice == '13':
        register_member(decrypt_data(user[1]))
    elif choice == '14':
        modify_member_information(decrypt_data(user[1]))
    elif choice == '15':
        delete_member(decrypt_data(user[1]))
    elif choice == '16':
        search_member(decrypt_data(user[1]))
    elif choice == '17':
        display_users(decrypt_data(user[1]))


def handle_system_admin_choice(choice, user):
    if choice == '1':
        add_consultant(decrypt_data(user[1]))
    elif choice == '2':
        modify_consultant(decrypt_data(user[1]))
    elif choice == '3':
        delete_consultant(decrypt_data(user[1]))
    elif choice == '4':
        reset_consultant_password(decrypt_data(user[1]))
    elif choice == '5':
        backup_system(decrypt_data(user[1]))
    elif choice == '6':
        restore_system(decrypt_data(user[1]))
    elif choice == '7':
        view_logs(decrypt_data(user[1]))
    elif choice == '8':
        register_member(decrypt_data(user[1]))
    elif choice == '9':
        modify_member_information(decrypt_data(user[1]))
    elif choice == '10':
        delete_member(decrypt_data(user[1]))
    elif choice == '11':
        search_member(decrypt_data(user[1]))
    elif choice == '12':
        display_users(decrypt_data(user[1]))
    elif choice == '13':
        update_own_password(decrypt_data(user[1]))


def handle_consultant_choice(choice, user):
    if choice == '1':
        register_member(decrypt_data(user[1]))
    elif choice == '2':
        modify_member_information(decrypt_data(user[1]))
    elif choice == '3':
        search_member(decrypt_data(user[1]))
    elif choice == '4':
        update_own_password(decrypt_data(user[1]))


def add_consultant(user):
    user_info = get_user_info(include_username=True, include_password=True)
    user_info['role'] = 'consultant'
    database.add_user(**user_info)
    log_activity(user, 'Added a new user', suspicious=False)
    print("Consultant added successfully!")


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def is_valid_phone(phone):
    return re.match(r"^\d{8}$", phone)


def is_valid_username(username):
    errors = []

    if len(username) < 8 or len(username) > 10:
        errors.append("Username must have a length between 8 and 10 characters.")

    if not re.match(r"^[a-zA-Z_]", username):
        errors.append("Username must start with a letter or underscore.")

    if not re.match(r"^[a-zA-Z0-9_'._]*$", username):
        errors.append(
            "Username can only contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.).")

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (encrypt_data(username),))
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        errors.append("Username is already taken.")

    return len(errors) == 0, errors


def is_valid_password(password):
    errors = []

    if len(password) < 12 or len(password) > 30:
        errors.append("Password must have a length between 12 and 30 characters.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")

    if not re.search(r"[~!@#$%&_\-=\\|\(){}[\]:;'<>,.?/]", password):
        errors.append("Password must contain at least one special character.")

    return len(errors) == 0, errors


def get_user_info(include_username=False, include_password=False, include_optional=False):
    user_info = {}

    if include_username:
        while True:
            username = input("Username: ")
            valid, errors = is_valid_username(username)
            if valid:
                user_info['username'] = username
                break
            else:
                print("Invalid username. Please correct the following errors:")
                for error in errors:
                    print("-", error)

    if include_password:
        while True:
            password = input("Password: ")
            valid, errors = is_valid_password(password)
            if valid:
                user_info['password'] = password
                break
            else:
                print("Invalid password. Please correct the following errors:")
                for error in errors:
                    print("-", error)

    user_info['first_name'] = input("First Name: ")
    user_info['last_name'] = input("Last Name: ")

    if include_optional:
        while True:
            try:
                user_info['age'] = int(input("Age: "))
                break
            except ValueError:
                print("Age must be an integer.")

        while True:
            gender = input("Gender (M/F): ").upper()
            if gender in ['M', 'F']:
                user_info['gender'] = gender
                break
            else:
                print("Gender must be 'M' or 'F'.")

        while True:
            try:
                user_info['weight'] = float(input("Weight: "))
                break
            except ValueError:
                print("Weight must be a number.")

        user_info['address'] = input("Address: ")

        while True:
            zip_code = input("Zip Code (DDDDXX): ")
            if re.match(r"^\d{4}[A-Za-z]{2}$", zip_code):
                user_info['zip_code'] = zip_code.upper()
                break
            else:
                print("Invalid zip code format. Example: 1234AB")

        print("Choose City:")
        cities = ["Amsterdam", "Rotterdam", "Utrecht", "The Hague", "Eindhoven", "Groningen", "Maastricht", "Haarlem",
                  "Nijmegen", "Arnhem"]
        for index, city in enumerate(cities, start=1):
            print(f"{index}. {city}")

        while True:
            city_index = input("Enter the number corresponding to your city choice: ")
            if city_index.isdigit() and 1 <= int(city_index) <= len(cities):
                user_info['city'] = cities[int(city_index) - 1]
                break
            else:
                print("Invalid input. Enter the number corresponding to your city choice.")

        while True:
            email = input("Email: ")
            if is_valid_email(email):
                user_info['email'] = email
                break
            else:
                print("Invalid email format.")

        while True:
            phone = input("Phone (last 8 digits): ")
            if is_valid_phone(phone):
                user_info['phone'] = f"+31-6-{phone}"
                break
            else:
                print("Phone number must be exactly 8 digits.")

    return user_info


def add_system_administrator(user):
    user_info = get_user_info(include_username=True, include_password=True)
    user_info['role'] = 'system_admin'
    database.add_user(user_info['username'], user_info['password'], user_info['role'],
                      user_info['first_name'], user_info['last_name'],
                      user_info.get('zip_code'), user_info.get('age'), user_info.get('gender'),
                      user_info.get('weight'), user_info.get('address'), user_info.get('city'),
                      user_info.get('email'), user_info.get('phone'))
    log_activity(user_info['username'], f'{user} Added system administrator')
    print("System Administrator added successfully!")


def register_member(user):
    user_info = get_user_info(include_username=True, include_password=True, include_optional=True)
    user_info['role'] = 'member'
    database.add_user(**user_info, is_new=True)
    log_activity(user, f'Registered new member',suspicious=False)
    print("Member registered successfully!")


def modify_member_information(user):
    username = input("Enter Member Username to modify: ")
    encrypted_username = encrypt_data(username)
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    try:
        # Check if the user exists
        cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
        existing_user = cursor.fetchone()
        if existing_user:
            updates = get_user_info(include_optional=True)
            update_fields = []
            update_values = []

            # Prepare the update statement dynamically for non-empty fields
            for field, value in updates.items():
                if value:  # Only include non-empty fields
                    update_fields.append(f"{field} = ?")
                    update_values.append(encrypt_data(value) if isinstance(value, str) else value)

            if update_fields:  # Only proceed if there are fields to update
                update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE username=?"
                cursor.execute(update_query, (*update_values, encrypted_username))
                conn.commit()
                log_activity(user, f'Modified member information for username {username}', additional_info=str(updates))
                print("Member information updated successfully!")
            else:
                print("No updates provided.")
                log_activity(user, f'No changes made for username {username}', additional_info="No fields to update")
        else:
            print("Member not found.")
            log_activity('System', f'{user} Failed to modify member information',
                         additional_info=f'Member {username} not found',
                         suspicious=True)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        log_activity('System', f'{user} Failed to modify member information',
                     additional_info=f'Error: {e}',
                     suspicious=True)
    finally:
        conn.close()


def search_member(user):
    search_key = input("Enter search key: ")
    results = database.search_user(search_key, encrypt_data('member'))
    for result in results:
        print(result)
    log_activity('System', f'{user} Searched for member', additional_info=search_key)


def search_super_admin(user):
    search_key = input("Enter search key: ")
    results = database.search_user(search_key, encrypt_data('super_admin'))
    for result in results:
        print(result)
    log_activity('System', f'{user} Searched for super admin', additional_info=search_key)


def search_system_admin(user):
    search_key = input("Enter search key: ")
    results = database.search_user(search_key, encrypt_data('system_admin'))
    for result in results:
        print(result)
    log_activity('System', f'{user} Searched for system admin', additional_info=search_key)


def search_consultant(user):
    search_key = input("Enter search key: ")
    results = database.search_user(search_key, encrypt_data('consultant'))
    for result in results:
        print(result)
    log_activity('System', f'{user} Searched for consultant', additional_info=search_key)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))


def update_own_password(user):
    username = input("Username: ")
    encrypted_username = encrypt_data(username)

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (encrypted_username,))
    result = cursor.fetchone()

    if not result:
        decrypted_username = decrypt_data(encrypted_username)
        print("Username does not exist.")
        log_activity(decrypted_username, f'{user} has Failed password update',
                     additional_info='Username does not exist', suspicious=True)
        conn.close()
        return

    old_password_hash = result[0]
    old_password = input("Old Password: ")

    if not check_password(old_password_hash, old_password):
        print("Old password is incorrect.")
        log_activity(username, f'{user} Failed password update', additional_info='Incorrect old password',
                     suspicious=True)
        conn.close()
        return

    new_password = input("New Password: ")
    valid, errors = is_valid_password(new_password)

    if not valid:
        print("Invalid password. Please correct the following errors:")
        for error in errors:
            print("-", error)
        log_activity(username, f'{user} has Failed password update', additional_info='Invalid new password',
                     suspicious=True)
        conn.close()
        return

    new_password_hash = hash_password(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password_hash, encrypted_username))
    conn.commit()
    conn.close()

    log_activity(username, 'Updated own password')
    print("Password updated successfully.")


def view_logs(user):
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT log_entry FROM logs''')
    logs = cursor.fetchall()
    conn.close()
    for log in logs:
        decrypted_log = decrypt_data(log[0])
        print(decrypted_log)

    log_activity('System', f'{user} Viewed logs')


def backup_system(user):
    backup_db_file = 'unique_meal_backup.db'
    zip_file_name = 'unique_meal_backup.zip'

    try:
        # Remove existing backup file if it exists
        if os.path.exists(backup_db_file):
            os.remove(backup_db_file)

        # Copy the current database to a backup database file
        shutil.copyfile('unique_meal.db', backup_db_file)

        # Create a zip file and add the backup database file to it
        with zipfile.ZipFile(zip_file_name, 'w') as zipf:
            zipf.write(backup_db_file)

        print("System backup created successfully as a zip file.")
        log_activity(user, 'Created system backup')

    except Exception as e:
        print(f"Failed to create system backup: {e}")
        log_activity(user, 'Failed to create system backup', additional_info=str(e), suspicious=True)

    finally:
        # Clean up the temporary backup database file
        if os.path.exists(backup_db_file):
            os.remove(backup_db_file)


def restore_system(user):
    backup_db_file = 'unique_meal_backup.db'
    zip_file_name = 'unique_meal_backup.zip'

    try:
        # Extract the backup database file from the zip file
        with zipfile.ZipFile(zip_file_name, 'r') as zipf:
            zipf.extract(backup_db_file)

        # Remove the current database file if it exists
        if os.path.exists('unique_meal.db'):
            os.remove('unique_meal.db')

        # Move the extracted backup database file to the original database location
        shutil.move(backup_db_file, 'unique_meal.db')

        print("System restored successfully from the zip backup.")
        log_activity(user, 'Created restored backup')

    except Exception as e:
        print(f"Failed to restore system from backup: {e}")
        log_activity(user, 'Failed to restore system backup', additional_info=str(e), suspicious=True)

    finally:
        # Clean up the extracted backup database file if it still exists
        if os.path.exists(backup_db_file):
            os.remove(backup_db_file)


def modify_consultant(user):
    username = input("Enter Username of consultant to modify: ")
    encrypted_username = encrypt_data(username)
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
        existing_user = cursor.fetchone()
        if existing_user:
            updates = get_user_info(include_optional=False)
            update_fields = []
            update_values = []

            for field, value in updates.items():
                if value:  # Only include non-empty fields
                    update_fields.append(f"{field} = ?")
                    update_values.append(encrypt_data(value) if isinstance(value, str) else value)

            if update_fields:  # Only proceed if there are fields to update
                update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE username=?"
                cursor.execute(update_query, (*update_values, encrypted_username))
                conn.commit()
                log_activity(user, f'Modified consultant information for username {encrypted_username}',
                             additional_info=str(updates))
                print("Consultant information updated successfully!")
            else:
                print("No updates provided.")
                log_activity(user, f'No changes made for username {username}', additional_info="No fields to update")
        else:
            print("Consultant not found.")
            log_activity('System', f'{user} Failed to modify consultant information',
                         additional_info=f'Consultant {username} not found',
                         suspicious=True)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        log_activity('System', f'{user} Failed to modify consultant information',
                     additional_info=f'Error: {e}',
                     suspicious=True)
    finally:
        conn.close()


def delete_consultant(user):
    username = input("Enter the username of the consultant to delete: ")
    encrypted_username = encrypt_data(username)
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    try:
        # Check if the user exists
        cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.execute("DELETE FROM users WHERE username=?", (encrypted_username,))
            conn.commit()
            print("Consultant deleted successfully.")
            log_activity(user, 'Deleted consultant', additional_info=f'Consultant username: {username}')
        else:
            print("Consultant not found.")
            log_activity('System', f'{user} Failed to delete consultant',
                         additional_info=f'Consultant {username} not found',
                         suspicious=True)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        log_activity('System', f'{user} Failed to delete consultant',
                     additional_info=f'Error: {e}',
                     suspicious=True)
    finally:
        conn.close()


def reset_consultant_password(user):
    username = input("Enter the username of the consultant to reset password: ")
    new_password = input("Enter the new temporary password: ")
    hashed_password = security.hash_password(new_password)

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (encrypt_data(username),))
    result = cursor.fetchone()

    if result:
        # User exists, proceed to update password
        cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, encrypt_data(username)))
        conn.commit()
        log_activity(username, 'Reset consultant password')
        print("Consultant password reset successfully.")
    else:
        # User not found
        print("Consultant not found.")
        log_activity('System', f'{user} failed to reset consultant password',
                     additional_info=f'Consultant {username} not found', suspicious=True)

    conn.commit()
    conn.close()


def delete_member(user):
    member_id = input("Enter the ID of the member to delete: ")

    try:
        # Establishing connection to the database
        conn = sqlite3.connect('unique_meal.db')
        cursor = conn.cursor()

        # Check if member exists
        cursor.execute("SELECT * FROM users WHERE member_id=?", (encrypt_data(member_id),))
        member = cursor.fetchone()
        if member is None:
            print("Member not found.")
            log_activity('System', f'{user} Failed to delete member')
            return

        cursor.execute("DELETE FROM users WHERE member_id=?", (encrypt_data(member_id),))
        conn.commit()
        print("Member deleted successfully.")
        log_activity(user, 'Deleted member')

        conn.commit()
    except sqlite3.Error as e:
        print(f"An error occurred while deleting member: {e}")


def add_admin(user):
    user_info = get_user_info(include_username=True, include_password=True, include_optional=False)
    database.add_user(username=user_info['username'], password=user_info['password'], role='super_admin',
                      first_name=user_info['first_name'], last_name=user_info['last_name'])
    log_activity(user_info['username'], f'{user} Added administrator')
    print("New admin added successfully.")


def modify_admin(user):
    username = input("Enter Admin Username to modify: ")
    encrypted_username = encrypt_data(username)
    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM users WHERE username=?", (encrypted_username,))
        existing_user = cursor.fetchone()
        if existing_user:
            updates = get_user_info(include_optional=False)
            update_fields = []
            update_values = []

            for field, value in updates.items():
                if value:  # Only include non-empty fields
                    update_fields.append(f"{field} = ?")
                    update_values.append(encrypt_data(value) if isinstance(value, str) else value)

            if update_fields:
                update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE username=?"
                cursor.execute(update_query, (*update_values, encrypted_username))
                conn.commit()
                log_activity(user, f'Modified admin information for username {username}', additional_info=str(updates))
                print("Admin information updated successfully!")
            else:
                print("No updates provided.")
                log_activity(user, f'No changes made for username {username}', additional_info="No fields to update")
        else:
            print("Admin not found.")
            log_activity('System', f'{user} Failed to modify admin information',
                         additional_info=f'Admin {username} not found',
                         suspicious=True)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        log_activity('System', f'{user} Failed to modify admin information',
                     additional_info=f'Error: {e}',
                     suspicious=True)
    finally:
        conn.close()

def delete_admin(user):
    username = input("Enter the username of the admin to delete: ")

    encrypted_username = encrypt_data(username)

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username = ?', (encrypted_username,))
        admin = cursor.fetchone()

        if admin:
            confirm = input(f"Are you sure you want to delete admin {username}? (yes/no): ")
            if confirm.lower() == 'yes':
                cursor.execute('DELETE FROM users WHERE username = ?', (encrypted_username,))
                conn.commit()
                print("Admin deleted successfully.")
                log_activity(user, 'Deleted admin', additional_info=f'Admin username: {username}')
            else:
                print("Deletion canceled.")
                log_activity(user, 'Canceled admin deletion', additional_info=f'Admin username: {username}')
        else:
            print("Admin not found.")
            log_activity(user, 'Failed to delete admin', additional_info=f'Admin username: {username}', suspicious=True)

    except Exception as e:
        print(f"An error occurred while trying to delete the admin: {e}")
        log_activity(user, 'Error occurred during admin deletion',
                     additional_info=f'Admin username: {username}, Error: {e}', suspicious=True)

    conn.close()


def reset_admin_password(user):
    username = input("Enter the username of the admin to reset password: ")
    new_password = input("Enter the new temporary password: ")

    valid, errors = is_valid_password(new_password)
    if not valid:
        print("Invalid password. Please correct the following errors:")
        for error in errors:
            print("-", error)
        return

    hashed_password = database.hash_password(new_password)

    conn = sqlite3.connect('unique_meal.db')
    cursor = conn.cursor()

    cursor.execute('UPDATE users SET password = ? WHERE username = ? AND role = ?',
                   (hashed_password, username, 'super_admin'))

    if cursor.rowcount > 0:
        print("Admin password reset successfully.")
    else:
        print("Admin not found.")

    conn.commit()
    conn.close()


def display_users(user):
    results = database.display_users()

    for result in results:
        print(result)

    log_activity(f'{user}display_users', 'Displayed all users')
    print('\n')
