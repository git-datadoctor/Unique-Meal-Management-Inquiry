from auth import login
from menus import main_menu, super_admin_menu, system_admin_menu, consultant_menu
from database import init_db, add_super_admin, encrypt_data, decrypt_data, log_activity
from users_action import handle_super_admin_choice, handle_system_admin_choice, handle_consultant_choice

def main():
    init_db()
    add_super_admin()

    while True:
        choice = main_menu()
        if choice == '1':
            user = login()
            if user:
                log_activity(decrypt_data(user[1]), 'Successfully login', suspicious=False)
                encrypted_role = user[3]
                if encrypted_role == encrypt_data('super_admin'):
                    print("Welcome super_admin!")
                    print('\n')

                    while True:
                        sa_choice = super_admin_menu()
                        if sa_choice == '18':
                            break
                        handle_super_admin_choice(sa_choice, user)
                elif encrypted_role == encrypt_data('system_admin'):
                    print("Welcome system_admin!")
                    print('\n')

                    while True:
                        sa_choice = system_admin_menu()
                        if sa_choice == '14':
                            break
                        handle_system_admin_choice(sa_choice, user)
                elif encrypted_role == encrypt_data('consultant'):
                    print("Welcome consultant!")
                    print('\n')

                    while True:
                        c_choice = consultant_menu()
                        if c_choice == '5':
                            break
                        handle_consultant_choice(c_choice, user)
            else:
                log_activity("Invalid user", 'Invalid login attempted', suspicious=True)

        elif choice == '2':
            print("Exiting...")
            break

if __name__ == "__main__":
    main()
