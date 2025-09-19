import os 
import time
from datetime import datetime
import getpass, bcrypt
import mysql.connector
from utils import get_connection,header, DB_CONFIG
from entries_menu import create_vault, open_vault, edit_vault, delete_vault


#buat ngecek koneksi ke database
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

#clean look biar rapi
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

#fungsi registrasi user baru input username:master_password
def registration():
    header("USER REGISTRATION", None)
    username = input("Enter a username: ")
    master_password = getpass.getpass("Enter a master password: ")
    password_bytes = master_password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    if not username or not master_password:
        print("\n Username and password cannot be empty."); time.sleep(2); return
    connection = get_connection()
    if not hasattr(connection, 'cursor'):
        print(f"Failed to connect to the database. {connection}"); time.sleep(2); return
    cursor = None
    try:
        cursor = connection.cursor()
        query_check = "SELECT username FROM users WHERE username = %s"
        cursor.execute(query_check, (username,))
        if cursor.fetchone():
            print("\n Username already exists. Please choose a different username."); time.sleep(2); return
        query_insert = "INSERT INTO users (username, master_password) VALUES (%s, %s)"
        cursor.execute(query_insert, (username, hashed_password))
        connection.commit()
        print("\n Registration successful! You can log in now."); time.sleep(2)
    except mysql.connector.Error as err:
        print(f"\n Database error: {err}"); time.sleep(2)
    finally:
        if cursor: cursor.close()
        if connection.is_connected():
            connection.close()

def vault_menu(username):
    while True:
        header("VAULT MENU", username)
        print("1. Create Vault\n 2. Open vault\n 3. Edit vault\n 4. Delete vault\n 5. Back to main menu")
        choice = input("Please select an option: ")
        if choice == '1':
            create_vault(username)
        elif choice == '2':
            open_vault(username)
        elif choice == '3':
            edit_vault(username)
        elif choice == '4':
            delete_vault(username)
        elif choice == '5':
            break
        else:
            print("Invalid choice, please try again."); time.sleep(2)

# fungsi login pake username:master_password
def login():
    header("USER LOGIN", None)
    username = input("Enter your username: ").strip()
    master_password = getpass.getpass("Enter your master password: ").strip()
    connection = get_connection()
    if not hasattr(connection, 'cursor'):
        print(f"Failed to connect to the database. {connection}"); time.sleep(2); return
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        query_check = "SELECT username, master_password FROM users WHERE username = %s"
        cursor.execute(query_check, (username,))
        result = cursor.fetchone()
        if result and bcrypt.checkpw(master_password.encode('utf-8'), result['master_password'].encode('utf-8')):
            print(f"\n Login successfully! Welcome, {result['username']}."); time.sleep(3)
            return result['username']
        else:
            print("\n Login failed. Username or Master Password is incorrect."); time.sleep(3)
            return None
    except mysql.connector.Error as err:
        print(f"\n Database error: {err}"); time.sleep(3)
        return None
    finally:
        if cursor: cursor.close()
        connection.close()

#Main menu untuk menu awal
def main_menu():
    while True:
        header("MAIN MENU", None)
        print("1. Login")
        print("2. Register")
        print("3. Check Database Connection")
        print("4. Exit/logout")

        choice = input("Please select an option: ")
        if choice == '1':
            username = login()
            if username:
                vault_menu(username)
        elif choice == '2':
            registration()
        elif choice == '3':
            check_connection_db()
        elif choice == '4':
            print("Logout."); break
        else:
            print("Invalid choice, please try again. (1/2/3/4)"); time.sleep(2)

if __name__ == "__main__":
    main_menu()