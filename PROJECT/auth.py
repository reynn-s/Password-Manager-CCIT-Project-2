import mysql.connector
import getpass, bcrypt
import time
from header import header
from database import get_connection

def registration():
    header("USER REGISTRATION", None)
    username = input("Enter a username: ")
    master_password = getpass.getpass("Enter a password: ")
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
        query_insert = "INSERT INTO users (username, password, ) VALUES (%s, %s)"
        cursor.execute(query_insert, (username, hashed_password))
        connection.commit()
        print("\n Registration successful! You can log in now."); time.sleep(2)
    except mysql.connector.Error as err:
        print(f"\n Database error: {err}"); time.sleep(2)
    finally:
        if cursor: cursor.close()
        if connection.is_connected():
            connection.close()


def login():
    header("USER LOGIN", None)
    username = input("Enter your username: ").strip()
    master_password = getpass.getpass("Enter your password: ").strip()
    connection = get_connection()
    if not hasattr(connection, 'cursor'):
        print(f"Failed to connect to the database. {connection}"); time.sleep(2); return
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        query_check = "SELECT username, password FROM users WHERE username = %s"
        cursor.execute(query_check, (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(master_password.encode('utf-8'), user['password'].encode('utf-8')):
            print(f"\n Login successfully! Welcome, {username}."); time.sleep(2)
            vault_menu(username)
        else:
            print("\n Login failed. Username or Password is incorrect."); time.sleep(2)
            return None
    except mysql.connector.Error as err:
        print(f"\n Database error: {err}"); time.sleep(2)
        return None
    finally:
        if cursor: cursor.close()
        connection.close()
        