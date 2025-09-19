import os 
from datetime import datetime

def header(title, username=None):
    clear_screen()
    now = datetime.now()
    current_time = now.strftime("%A, %d %B %Y")
    print("█" * 70)
    print(f"PASSWORD MANAGER | (time: {current_time})".center(70))
    if username:
        print(f"Logged in as: {username}".center(70))
        print("█" * 70)
        print(f"\n=== {title} ===\n")

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')