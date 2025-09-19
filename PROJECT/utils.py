import os, time
from datetime import datetime
import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Telormatabebek!",
    "database": "project_db",
    "connection_timeout": 5
}

def get_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return err

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def header(title, username=None):
    clear_screen()
    now = datetime.now().strftime("%A, %d %B %Y")
    print("-#" * 35)
    print(f"PASSWORD MANAGER <||> (time: {now})".center(70))
    if username:
        print(f"Logged in as: {username}".center(70))
    print("-#" * 35)
    print(f"\n=== {title} ===\n")
