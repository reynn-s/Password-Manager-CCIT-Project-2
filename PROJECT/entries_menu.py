import time
import getpass
import mysql.connector
import bcrypt
from utils import get_connection, header

# ----------------- SMALL HELPERS -----------------
def get_user_id(conn, username: str) -> int | None:
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_user FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        return row["id_user"] if row else None
    finally:
        cur.close()

def hash_pw(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_pw(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def input_nonempty(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("Field cannot be empty.")

def choose_index(max_n: int, prompt="Select number: ") -> int | None:
    s = input(prompt).strip()
    if not s.isdigit():
        return None
    i = int(s)
    if 1 <= i <= max_n:
        return i
    return None

# List current user's vaults; returns list of dicts
def list_user_vaults(conn, id_user: int):
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT id_vault, vault_name, description FROM vaults WHERE id_user=%s ORDER BY vault_name",
            (id_user,),
        )
        return cur.fetchall()
    finally:
        cur.close()

# Get a vault row for this user by id_vault
def get_user_vault(conn, id_user: int, id_vault: int):
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT id_vault, vault_name, vault_password, description FROM vaults WHERE id_user=%s AND id_vault=%s",
            (id_user, id_vault),
        )
        return cur.fetchone()
    finally:
        cur.close()

# ----------------- VAULT ACTIONS -----------------
def create_vault(username: str):
    conn = get_connection()
    if isinstance(conn, mysql.connector.Error):
        print("DB connection failed.")
        time.sleep(1); return

    try:
        id_user = get_user_id(conn, username)
        if not id_user:
            print("User not found."); time.sleep(1); return

        header("CREATE VAULT", username)
        vault_name = input_nonempty("Vault name: ")
        desc = input("Description (optional): ").strip()
        mpw = getpass.getpass("Set vault password: ")
        if not mpw:
            print("Vault password cannot be empty."); time.sleep(1); return

        hashed = hash_pw(mpw)
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO vaults (id_user, vault_name, vault_password, description) VALUES (%s,%s,%s,%s)",
                (id_user, vault_name, hashed, desc or None),
            )
            conn.commit()
            print("✅ Vault created.")
        except mysql.connector.Error as e:
            if e.errno == 1062:
                print("❌ You already have a vault with that name.")
            else:
                print(f"DB error: {e}")
        finally:
            cur.close()
        time.sleep(1)
    finally:
        conn.close()

def open_vault(username: str):
    conn = get_connection()
    if isinstance(conn, mysql.connector.Error):
        print("DB connection failed.")
        time.sleep(1); return

    try:
        id_user = get_user_id(conn, username)
        if not id_user:
            print("User not found."); time.sleep(1); return

        # list vaults
        header("OPEN VAULT", username)
        vaults = list_user_vaults(conn, id_user)
        if not vaults:
            print("You have no vaults yet."); time.sleep(1); return

        for i, v in enumerate(vaults, 1):
            print(f"{i}. {v['vault_name']}  —  {v.get('description') or ''}")
        idx = choose_index(len(vaults))
        if idx is None:
            print("Invalid selection."); time.sleep(1); return

        chosen = vaults[idx - 1]
        # password prompt
        mpw = getpass.getpass(f"Enter vault password for '{chosen['vault_name']}': ")
        row = get_user_vault(conn, id_user, chosen["id_vault"])
        if not row or not check_pw(mpw, row["vault_password"]):
            print("❌ Wrong vault password.")
            time.sleep(1); return

        # success -> entries submenu
        entries_menu(conn, username, id_user, row["id_vault"], row["vault_name"])
    finally:
        conn.close()

def edit_vault(username: str):
    conn = get_connection()
    if isinstance(conn, mysql.connector.Error):
        print("DB connection failed.")
        time.sleep(1); return

    try:
        id_user = get_user_id(conn, username)
        if not id_user:
            print("User not found."); time.sleep(1); return

        header("EDIT VAULT", username)
        vaults = list_user_vaults(conn, id_user)
        if not vaults:
            print("You have no vaults yet."); time.sleep(1); return

        for i, v in enumerate(vaults, 1):
            print(f"{i}. {v['vault_name']}  —  {v.get('description') or ''}")
        idx = choose_index(len(vaults))
        if idx is None:
            print("Invalid selection."); time.sleep(1); return
        chosen = vaults[idx - 1]

        mpw = getpass.getpass(f"Enter vault password for '{chosen['vault_name']}': ")
        row = get_user_vault(conn, id_user, chosen["id_vault"])
        if not row or not check_pw(mpw, row["vault_password"]):
            print("❌ Wrong vault password.")
            time.sleep(1); return

        # Ask what to change
        print("\nLeave a field empty to keep current value.")
        new_name = input(f"New vault name (current: {chosen['vault_name']}): ").strip()
        new_desc = input("New description: ").strip()
        change_pw = input("Change vault password? (y/N): ").strip().lower() == 'y'
        new_hash = None
        if change_pw:
            mpw = getpass.getpass("New vault password: ")
            if not mpw:
                print("Password cannot be empty."); time.sleep(1); return
            new_hash = hash_pw(mpw)

        # Build dynamic UPDATE safely
        sets = []
        params = []
        if new_name:
            sets.append("vault_name=%s")
            params.append(new_name)
        if change_pw:
            sets.append("vault_password=%s")
            params.append(new_hash)
        if new_desc != "":
            sets.append("description=%s")
            params.append(new_desc or None)

        if not sets:
            print("Nothing to update.")
            time.sleep(1); return

        q = f"UPDATE vaults SET {', '.join(sets)} WHERE id_user=%s AND id_vault=%s"
        params.extend([id_user, chosen["id_vault"]])

        cur = conn.cursor()
        try:
            cur.execute(q, tuple(params))
            conn.commit()
            print("✅ Vault updated.")
        except mysql.connector.Error as e:
            # 1451: cannot update parent due to FK (if ON UPDATE CASCADE missing)
            if e.errno in (1451,):
                print("❌ Rename failed due to FK. Add ON UPDATE CASCADE to fk_entries_vault_composite (see note).")
            elif e.errno == 1062:
                print("❌ You already have a vault with that name.")
            else:
                print(f"DB error: {e}")
        finally:
            cur.close()
        time.sleep(1)
    finally:
        conn.close()

def delete_vault(username: str):
    conn = get_connection()
    if isinstance(conn, mysql.connector.Error):
        print("DB connection failed.")
        time.sleep(1); return

    try:
        id_user = get_user_id(conn, username)
        if not id_user:
            print("User not found."); time.sleep(1); return

        header("DELETE VAULT", username)
        vaults = list_user_vaults(conn, id_user)
        if not vaults:
            print("You have no vaults yet."); time.sleep(1); return

        for i, v in enumerate(vaults, 1):
            print(f"{i}. {v['vault_name']}  —  {v.get('description') or ''}")
        idx = choose_index(len(vaults))
        if idx is None:
            print("Invalid selection."); time.sleep(1); return
        chosen = vaults[idx - 1]

        # verify password
        mpw = getpass.getpass(f"Enter vault password for '{chosen['vault_name']}' to confirm: ")
        row = get_user_vault(conn, id_user, chosen["id_vault"])
        if not row or not check_pw(mpw, row["vault_password"]):
            print("❌ Wrong vault password.")
            time.sleep(1); return

        really = input("Are you sure you want to delete this vault? (type 'DELETE' to confirm): ").strip()
        if really != "DELETE":
            print("Cancelled.")
            time.sleep(1); return

        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM vaults WHERE id_user=%s AND id_vault=%s", (id_user, chosen["id_vault"]))
            conn.commit()
            print("🗑️ Vault deleted (entries removed via CASCADE).")
        except mysql.connector.Error as e:
            print(f"DB error: {e}")
        finally:
            cur.close()
        time.sleep(1)
    finally:
        conn.close()

# ----------------- ENTRIES SUBMENU -----------------
def entries_menu(conn, username: str, id_user: int, id_vault: int, vault_name: str):
    while True:
        header(f"VAULT: {vault_name}", username)
        print("1. Add entry\n2. List entries\n3. Edit entry\n4. Delete entry\n5. Exit to vault menu")
        choice = input("Select: ").strip()
        if choice == '1':
            add_entry(conn, id_user, id_vault, vault_name)
        elif choice == '2':
            list_entries(conn, id_user, id_vault, vault_name, pause=True)
        elif choice == '3':
            edit_entry(conn, id_user, id_vault, vault_name)
        elif choice == '4':
            delete_entry(conn, id_user, id_vault, vault_name)
        elif choice == '5':
            break
        else:
            print("Invalid choice."); time.sleep(1.5)

def list_entries(conn, id_user: int, id_vault: int, vault_name: str, pause=False):
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT e.id_entry, e.website_url, e.site_username, e.site_password, e.description
            FROM vault_entries e
            JOIN vaults v ON v.id_vault = e.id_vault AND v.vault_name = e.vault_name
            WHERE v.id_user=%s AND v.id_vault=%s AND v.vault_name=%s
            ORDER BY e.website_url, e.id_entry
        """, (id_user, id_vault, vault_name))
        rows = cur.fetchall()
        if not rows:
            print("(no entries)")
        else:
            for i, r in enumerate(rows, 1):
                print(f"{i}. {r['website_url']} | {r['site_username']} | {r['site_password']} | {r.get('description') or ''}")
                print("Website | Username | Password | Description")
        if pause:
            input("\nEnter to continue...")
        return rows
    finally:
        cur.close()

def add_entry(conn, id_user: int, id_vault: int, vault_name: str):
    print()
    website = input_nonempty("Website/URL: ")
    site_user = input_nonempty("Site username: ")
    site_pass = getpass.getpass("Site password (hidden input): ").strip()
    desc = input("Description (optional): ").strip()

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO vault_entries (id_vault, vault_name, website_url, site_username, site_password, description)
            SELECT %s, %s, %s, %s, %s, %s
            FROM dual
            WHERE EXISTS (SELECT 1 FROM vaults v WHERE v.id_user=%s AND v.id_vault=%s AND v.vault_name=%s)
        """, (id_vault, vault_name, website, site_user, site_pass or None, desc or None,
              id_user, id_vault, vault_name))
        if cur.rowcount == 0:
            print("❌ Not authorized for this vault.")
        else:
            conn.commit()
            print("✅ Entry added.")
    except mysql.connector.Error as e:
        print(f"DB error: {e}")
    finally:
        cur.close()
    time.sleep(1.5)

def edit_entry(conn, id_user: int, id_vault: int, vault_name: str):
    rows = list_entries(conn, id_user, id_vault, vault_name, pause=False)
    if not rows:
        time.sleep(1.5); return
    idx = choose_index(len(rows), "Entry number to edit: ")
    if idx is None:
        print("Invalid selection."); time.sleep(1.5); return
    target = rows[idx - 1]

    print("\nLeave empty to keep current.")
    website = input(f"Website/URL ({target['website_url']}): ").strip() or target['website_url']
    site_user = input(f"Site username ({target['site_username']}): ").strip() or target['site_username']
    site_pass = input(f"Site password ({target['site_password']}): ").strip() or target['site_password']
    desc = input(f"Description ({target.get('description') or ''}): ").strip()
    if desc == "":
        desc = target.get('description')

    cur = conn.cursor()
    try:
        # scoped UPDATE with join to enforce owner
        cur.execute("""
            UPDATE vault_entries e
            JOIN vaults v ON v.id_vault=e.id_vault AND v.vault_name=e.vault_name
            SET e.website_url=%s, e.site_username=%s, e.site_password=%s, e.description=%s
            WHERE e.id_entry=%s AND v.id_user=%s AND v.id_vault=%s AND v.vault_name=%s
        """, (website, site_user, site_pass, desc, target['id_entry'], id_user, id_vault, vault_name))
        if cur.rowcount == 0:
            print("❌ Not authorized or entry not found.")
        else:
            conn.commit()
            print("✅ Entry updated.")
    except mysql.connector.Error as e:
        print(f"DB error: {e}")
    finally:
        cur.close()
    time.sleep(1.5)

def delete_entry(conn, id_user: int, id_vault: int, vault_name: str):
    rows = list_entries(conn, id_user, id_vault, vault_name, pause=False)
    if not rows:
        time.sleep(1.5); return
    idx = choose_index(len(rows), "Entry number to delete: ")
    if idx is None:
        print("Invalid selection."); time.sleep(1.5); return
    target = rows[idx - 1]

    really = input("Type 'DELETE' to confirm: ").strip()
    if really != "DELETE":
        print("Cancelled."); time.sleep(1.5); return

    cur = conn.cursor()
    try:
        cur.execute("""
            DELETE e FROM vault_entries e
            JOIN vaults v ON v.id_vault=e.id_vault AND v.vault_name=e.vault_name
            WHERE e.id_entry=%s AND v.id_user=%s AND v.id_vault=%s AND v.vault_name=%s
        """, (target['id_entry'], id_user, id_vault, vault_name))
        if cur.rowcount == 0:
            print("❌ Not authorized or entry not found.")
        else:
            conn.commit()
            print("🗑️ Entry deleted.")
    except mysql.connector.Error as e:
        print(f"DB error: {e}")
    finally:
        cur.close()
    time.sleep(1.5)
