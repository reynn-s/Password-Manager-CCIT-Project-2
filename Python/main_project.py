def create_vault():


def open_vault():


def main_menu():
    print("Welcome to the Main Menu")
    while True:
        print("1. Create Vault")
        print("2. Open Vault")
        print("3. Exit/logout")

        choice = input("Please select an option: ")
        if choice == '1':
            create_vault()
        elif choice == '2':
            open_vault()
        elif choice == '3':
            print("Logout.")
        else:
            print("Invalid choice, please try again.")
            main_menu()