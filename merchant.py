import hashlib
import time
import mysql.connector

# MySQL Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",  
    password="sagar333",  
    database="blockchain_db"
)
cursor = db.cursor()

# Function to Generate MID
def generate_mid(merchant_name, password):
    timestamp = str(int(time.time()))  
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    raw_data = merchant_name + timestamp + password_hash
    final_hash = hashlib.sha256(raw_data.encode()).hexdigest()
    mid = final_hash[:16].upper()  
    return mid

# Function to Register a Merchant
def register_merchant(name, password, balance, ifsc_code):
    mid = generate_mid(name, password)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Insert into MySQL
    sql = "INSERT INTO merchants (name, password_hash, account_balance, ifsc_code, mid) VALUES (%s, %s, %s, %s, %s)"
    values = (name, password_hash, balance, ifsc_code, mid)

    cursor.execute(sql, values)
    db.commit()

    print(f"Merchant '{name}' registered successfully with MID: {mid}")

# Example Usage
register_merchant("JohnStore", "securePass123", 5000.00, "HDFC0001234")
