import hashlib
import time
import mysql.connector


# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="sagar333",
    database="blockchain_db"
)
cursor = db.cursor()

def generate_uid(username, password):
    """Generates a 16-digit unique UID using username, timestamp, and hashed password."""
    timestamp = str(int(time.time()))
    raw_string = username + timestamp + password
    uid = hashlib.sha256(raw_string.encode()).hexdigest()[:16]  # Take first 16 chars
    return uid.upper()

def generate_mmid(uid, mobile_number):
    """Generates MMID using UID and mobile number."""
    mmid = hashlib.sha256((uid + mobile_number).encode()).hexdigest()[:16]
    return mmid.upper()

def register_user(username, password, ifsc_code, pin, mobile_number,balance):
    """Registers a user, generates UID & MMID, and stores them in the database."""
    uid = generate_uid(username, password)  # Generate UID
    mmid = generate_mmid(uid, mobile_number)  # Generate MMID
    password_hash = hashlib.sha256(password.encode()).hexdigest()  # Hash password
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()  # Hash PIN

    sql = """INSERT INTO users (uid, username, ifsc_code, password_hash, pin_hash, mobile_number, mmid,balance) 
             VALUES (%s, %s, %s, %s, %s, %s, %s,%s)"""
    values = (uid, username, ifsc_code, password_hash, pin_hash, mobile_number, mmid,balance)

    try:
        cursor.execute(sql, values)
        db.commit()
        print(f"User registered successfully! UID: {uid}, MMID: {mmid}")
    except mysql.connector.Error as err:
        print("Error:", err)

# Example Registration
register_user("Alice", "securePass123", "HDFC0001234", "1234", "9876543210","30000")
