# password_manager.py
# One-file CLI password manager per your spec:
# Login/Register -> Main Menu (Create/Open by name/Logout[0])
# -> Vault Menu (Add/List/Search[show password]/Edit/Delete/Lock[0])
#
# Storage: SQLite (users, vaults, entries)
# Crypto:  - stdlib PBKDF2-HMAC-SHA256 for user password hashing
#          - Fernet (cryptography) for vault password encryption

import os
import sqlite3
import base64
import secrets
import time
import platform
from datetime import datetime
from getpass import getpass
from typing import Optional, Tuple, List

# ---- external dep: cryptography ----
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # vault KDF only
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

DB_PATH = "passvault.db"

# User login (stdlib PBKDF2)
USER_KDF_ITERS = 260_000
USER_SALT_BYTES = 16
USER_HASH_LEN = 32

# Vault KDF (for Fernet key)
VAULT_KDF_ITERS = 200_000
VAULT_SALT_BYTES = 16

APP_NAME = "PassVault"
APP_TAGLINE = "simple. secure. local."
VERSION = "v0.1.0"

# ===================== UI (pure strings) =====================
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def line(width=72, ch="─"):
    return ch * width

def banner(title=APP_NAME, subtitle=None, width=72):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title_line = f" {title.upper()} "
    sub_line = f" {subtitle or (APP_TAGLINE + ' — ' + VERSION)} "
    info = f" {platform.system()} {platform.release()} | Python {platform.python_version()} | {ts} "

    print("╔" + "═" * (width - 2) + "╗")
    print("║" + title_line.center(width - 2, "·") + "║")
    print("╟" + "─" * (width - 2) + "╢")
    print("║" + sub_line.center(width - 2) + "║")
    print("║" + info.center(width - 2) + "║")
    print("╚" + "═" * (width - 2) + "╝")

def section(title, width=72):
    left = f" {title} "
    mid = max(0, width - len(left))
    print(left + "─" * mid)

def menu(items, width=72):
    for key, label in items:
        print(f"  [{key:>2}]  {label}")
    print("  " + line(width - 2))

def pause():
    input("\nPress Enter...")

# ===================== DB =====================
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email    TEXT UNIQUE NOT NULL,
        pw_salt  BLOB NOT NULL,
        pw_hash  BLOB NOT NULL,
        pw_iters INTEGER NOT NULL
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS vaults(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        salt BLOB NOT NULL,
        kdf_iters INTEGER NOT NULL,
        sentinel BLOB NOT NULL,
        UNIQUE(user_id, name),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS entries(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vault_id INTEGER NOT NULL,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        pwd_cipher BLOB NOT NULL,
        notes_cipher BLOB,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
      )
    """)
    return conn

# ===================== Auth (users) =====================
def _pbkdf2(pw: bytes, salt: bytes, length: int, iters: int) -> bytes:
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, dklen=length)

def user_hash_password(password: str) -> Tuple[bytes, bytes, int]:
    salt = secrets.token_bytes(USER_SALT_BYTES)
    dk = _pbkdf2(password.encode(), salt, USER_HASH_LEN, USER_KDF_ITERS)
    return salt, dk, USER_KDF_ITERS

def user_verify_password(password: str, salt: bytes, iters: int, stored_hash: bytes) -> bool:
    dk = _pbkdf2(password.encode(), salt, len(stored_hash), iters)
    return secrets.compare_digest(dk, stored_hash)

def register_user(conn, username: str, email: str, password: str) -> None:
    salt, pw_hash, iters = user_hash_password(password)
    conn.execute(
        "INSERT INTO users(username, email, pw_salt, pw_hash, pw_iters) VALUES(?,?,?,?,?)",
        (username, email, salt, pw_hash, iters)
    )
    conn.commit()

def login_user(conn, identity: str, password: str) -> Optional[dict]:
    cur = conn.execute(
        "SELECT id, username, email, pw_salt, pw_hash, pw_iters FROM users WHERE username=? OR email=?",
        (identity, identity)
    )
    row = cur.fetchone()
    if not row:
        return None
    uid, uname, email, pw_salt, pw_hash, iters = row
    if user_verify_password(password, pw_salt, iters, pw_hash):
        return {"id": uid, "username": uname, "email": email}
    return None

# ===================== Vault KDF (Fernet) =====================
def derive_vault_fernet(master_password: str, salt: bytes, iters: int) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)

# ===================== Vault API =====================
def create_vault(conn, user_id: int, name: str, master_password: str) -> None:
    salt = secrets.token_bytes(VAULT_SALT_BYTES)
    f = derive_vault_fernet(master_password, salt, VAULT_KDF_ITERS)
    sentinel = f.encrypt(b"ok")  # master verification token
    conn.execute(
        "INSERT INTO vaults(user_id, name, salt, kdf_iters, sentinel) VALUES(?,?,?,?,?)",
        (user_id, name, salt, VAULT_KDF_ITERS, sentinel)
    )
    conn.commit()

def list_vaults(conn, user_id: int) -> List[Tuple[int, str]]:
    cur = conn.execute("SELECT id, name FROM vaults WHERE user_id=? ORDER BY name", (user_id,))
    return list(cur.fetchall())

def open_vault_by_name(conn, user_id: int, vault_name: str, master_password: str):
    cur = conn.execute(
        "SELECT id, salt, kdf_iters, sentinel FROM vaults WHERE user_id=? AND name=?",
        (user_id, vault_name)
    )
    row = cur.fetchone()
    if not row:
        raise ValueError("Vault not found.")
    vault_id, salt, iters, sentinel = row
    f = derive_vault_fernet(master_password, salt, iters)
    try:
        if f.decrypt(sentinel) != b"ok":
            raise ValueError("Invalid master password.")
    except Exception:
        raise ValueError("Invalid master password.")
    return (conn, f, vault_id, vault_name)

# ===================== Entry CRUD =====================
def add_entry(handle, site: str, username: str, password: str, notes: str = "") -> None:
    conn, f, vault_id, _ = handle
    now = int(time.time())
    pwd_c = f.encrypt(password.encode())
    notes_c = f.encrypt(notes.encode()) if notes else None
    conn.execute(
        "INSERT INTO entries(vault_id, site, username, pwd_cipher, notes_cipher, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (vault_id, site, username, pwd_c, notes_c, now, now)
    )
    conn.commit()

def list_entries(handle) -> List[Tuple[int, str, str]]:
    conn, _, vault_id, _ = handle
    cur = conn.execute(
        "SELECT id, site, username FROM entries WHERE vault_id=? ORDER BY id", (vault_id,)
    )
    return list(cur.fetchall())

def get_entry(handle, entry_id: int):
    conn, f, vault_id, _ = handle
    cur = conn.execute(
        "SELECT id, site, username, pwd_cipher, IFNULL(notes_cipher, X'') "
        "FROM entries WHERE vault_id=? AND id=?",
        (vault_id, entry_id)
    )
    row = cur.fetchone()
    if not row:
        return None
    _id, site, user, pwd_c, notes_c = row
    pwd = f.decrypt(pwd_c).decode()
    notes = f.decrypt(notes_c).decode() if notes_c else ""
    return (_id, site, user, pwd, notes)

def search_entries_ids(handle, q: str) -> List[Tuple[int, str, str]]:
    """Find entries by site OR username; returns (id, site, username)."""
    conn, _, vault_id, _ = handle
    like = f"%{q}%"
    cur = conn.execute(
        "SELECT id, site, username FROM entries "
        "WHERE vault_id=? AND (site LIKE ? OR username LIKE ?) ORDER BY id",
        (vault_id, like, like)
    )
    return list(cur.fetchall())

# ===================== Flows =====================
def login_page(conn):
    while True:
        clear()
        banner("PasswordManager Login")
        menu([("1", "Login"), ("2", "Register"), ("0", "Exit")])
        c = input("> ").strip()
        if c == "1":
            ident = input("Username or Email: ").strip()
            pw = getpass("Password: ")
            user = login_user(conn, ident, pw)
            if user:
                main_menu(conn, user)
            else:
                print("Invalid credentials.")
                pause()
        elif c == "2":
            username = input("Choose username: ").strip()
            email = input("Email: ").strip()
            pw1 = getpass("Password: ")
            pw2 = getpass("Confirm password: ")
            if not username or not email or not pw1:
                print("All fields are required.")
            elif pw1 != pw2:
                print("Passwords do not match.")
            else:
                try:
                    register_user(conn, username, email, pw1)
                    print("✓ Registered. Please login.")
                except sqlite3.IntegrityError as e:
                    print(f"Error (duplicate username/email?): {e}")
            pause()
        elif c == "0":
            break
        else:
            print("Invalid option."); pause()

def main_menu(conn, user):
    while True:
        clear()
        banner(APP_NAME, subtitle=f"Hello, {user['username']}  ·  {user['email']}")
        section("MAIN MENU")
        menu([
            ("1", "Create vault"),
            ("2", "Open vault"),
            ("0", "Logout / back to login"),
        ])
        c = input("> ").strip()
        if c == "1":
            create_vault_flow(conn, user)
        elif c == "2":
            open_vault_flow(conn, user)
        elif c == "0":
            return
        else:
            print("Invalid option."); pause()

def create_vault_flow(conn, user):
    name = input("Vault name: ").strip()
    if not name:
        print("Name is required."); pause(); return
    master = getpass("Set master password: ")
    confirm = getpass("Confirm master password: ")
    if not master or master != confirm:
        print("Master passwords must match."); pause(); return
    try:
        create_vault(conn, user["id"], name, master)
        print(f"✓ Created vault '{name}'.")
    except sqlite3.IntegrityError:
        print("A vault with that name already exists.")
    pause()

def open_vault_flow(conn, user):
    while True:
        clear()
        banner("Open Vault", subtitle="Unlock by name")
        rows = list_vaults(conn, user["id"])
        if not rows:
            print("(You have no vaults yet)"); pause(); return

        section("YOUR VAULTS")
        # show only names
        for _, name in rows:
            print(f"  - {name}")
        print(line())

        menu([("1", "Unlock a vault by name"), ("0", "Back to main menu")])
        c = input("> ").strip()
        if c == "1":
            vname = input("Vault name: ").strip()
            if not vname:
                print("Please enter a vault name."); pause(); continue
            master = getpass("Master password: ")
            try:
                handle = open_vault_by_name(conn, user["id"], vname, master)
                vault_loop(handle)
            except Exception as e:
                print(f"Error: {e}")
                pause()
        elif c == "0":
            return
        else:
            print("Invalid option."); pause()

def vault_loop(handle):
    while True:
        clear()
        _, _, _, vname = handle
        banner(f"Vault: {vname}", subtitle="Unlocked")
        section("VAULT ACTIONS")
        menu([
            ("1", "Add password entry"),
            ("2", "List all entries"),
            ("3", "Search entries (show passwords)"),
            ("4", "Edit an entry"),
            ("5", "Delete an entry"),
            ("0", "Lock & return"),
        ])
        c = input("> ").strip()
        if c == "1":
            add_entry_flow(handle)
        elif c == "2":
            list_entries_flow(handle)
        elif c == "3":
            search_entries_flow_show_passwords(handle)   # revised: shows passwords
        elif c == "4":
            edit_entry_flow(handle)
        elif c == "5":
            delete_entry_flow(handle)
        elif c == "0":
            return
        else:
            print("Invalid option."); pause()

# -------- Inside-vault flows --------
def add_entry_flow(handle):
    site = input("Site/App (URL ok): ").strip()
    uname = input("Username: ").strip()
    pwd = getpass("Password: ")
    notes = input("Notes (optional): ").strip()
    if not site or not uname or not pwd:
        print("Site, username, and password are required.")
    else:
        add_entry(handle, site, uname, pwd, notes)
        print(f"✓ Saved entry for {site}.")
    pause()

def list_entries_flow(handle):
    rows = list_entries(handle)
    if not rows:
        print("(no entries yet)")
    else:
        print("\n ID | Site                         | Username")
        print("----+------------------------------+---------------------")
        for _id, site, user in rows:
            print(f"{_id:>3} | {site[:28]:<28} | {user[:19]:<19}")
    pause()

def search_entries_flow_show_passwords(handle):
    q = input("Search by site/username: ").strip()
    # first get IDs that match
    rows = search_entries_ids(handle, q)
    if not rows:
        print(f"(no matches for '{q}')")
        pause()
        return
    # For each match, decrypt to reveal password
    print("\n ID | Site                         | Username              | Password")
    print("----+------------------------------+-----------------------+----------------")
    for _id, site, user in rows:
        data = get_entry(handle, _id)  # decrypts
        if not data:
            continue
        _, site_d, user_d, pwd_d, _notes = data
        print(f"{_id:>3} | {site_d[:28]:<28} | {user_d[:21]:<21} | {pwd_d}")
    pause()

def edit_entry_flow(handle):
    try:
        eid = int(input("Entry ID to edit: ").strip())
    except ValueError:
        print("Invalid ID."); pause(); return
    cur = get_entry(handle, eid)
    if not cur:
        print("Not found."); pause(); return
    _id, site, user, _pwd, notes = cur
    print("Leave fields empty to keep current value.")
    ns = input(f"Site/App [{site}]: ").strip() or site
    nu = input(f"Username [{user}]: ").strip() or user
    change_pw = input("Change password? (y/N): ").strip().lower() == "y"
    if change_pw:
        np1 = getpass("New password: ")
        np2 = getpass("Confirm new password: ")
        if np1 != np2:
            print("Passwords do not match."); pause(); return
        np = np1
    else:
        np = None  # keep current
    nn = input(f"Notes [{notes}]: ").strip() or notes
    ok = edit_entry(handle, eid, ns, nu, np, nn)
    print("✓ Updated." if ok else "No change.")
    pause()

def edit_entry(handle, entry_id: int, site: str, username: str, password: Optional[str], notes: str) -> bool:
    # helper underlying edit (kept here for single-file clarity)
    conn, f, vault_id, _ = handle
    now = int(time.time())
    if password is None:
        cur = conn.execute(
            "SELECT pwd_cipher FROM entries WHERE vault_id=? AND id=?",
            (vault_id, entry_id)
        )
        row = cur.fetchone()
        if not row:
            return False
        pwd_c = row[0]
    else:
        pwd_c = f.encrypt(password.encode())
    notes_c = f.encrypt(notes.encode()) if notes else None
    cur = conn.execute(
        "UPDATE entries SET site=?, username=?, pwd_cipher=?, notes_cipher=?, updated_at=? "
        "WHERE vault_id=? AND id=?",
        (site, username, pwd_c, notes_c, now, vault_id, entry_id)
    )
    conn.commit()
    return cur.rowcount == 1

def delete_entry_flow(handle):
    try:
        eid = int(input("Entry ID to delete: ").strip())
    except ValueError:
        print("Invalid ID."); pause(); return
    confirm = input("Type 'DELETE' to confirm: ").strip()
    if confirm != "DELETE":
        print("Cancelled."); pause(); return
    ok = delete_entry(handle, eid)
    print("✓ Deleted." if ok else "Not found.")
    pause()

def delete_entry(handle, entry_id: int) -> bool:
    conn, _, vault_id, _ = handle
    cur = conn.execute("DELETE FROM entries WHERE vault_id=? AND id=?", (vault_id, entry_id))
    conn.commit()
    return cur.rowcount == 1

# ===================== Main =====================
if __name__ == "__main__":
    conn = db_connect()
    try:
        login_page(conn)
    finally:
        conn.close()
