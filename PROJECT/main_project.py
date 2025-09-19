import os 
import time
from datetime import datetime
from auth import registration, login
from database import DB_CONFIG, get_connection
from header import header
    
def check_connection_db():
    header("DATABASE CONNECTION CHECK", None)
    print(f"Checking database connection...'{DB_CONFIG['database']}'")
    connection = get_connection()
    if hasattr(connection, 'cursor'):
        print("Database connection successful.")
        connection.close()
    else:
        print("Database connection failed.")
        print(f"Error details: {connection}")
    input("Press Enter to return to the main menu...")



def main_menu():
    while True:
        header("Main Menu", None)
        print("1. Register")
        print("2. Login")
        print("3. Exit/logout")

        choice = input("Please select an option: ")
        if choice == '1':
            registration()
        elif choice == '2':
            login()
        elif choice == '3':
            check_connection_db()
        elif choice == '4':
            print("Logout.")
        else:
            print("Invalid choice, please try again. (1/2/3/4)"); time.sleep(2)

if __name__ == "__main__":
    main_menu()