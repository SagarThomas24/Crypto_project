import mysql.connector
import hashlib

# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="your_username",
    password="your_password",
    database="blockchain_db"
)
cursor = db.cursor()

def verify_transaction(mmid, pin, amount):
    """Verifies if the user has a valid MMID, correct PIN, and sufficient balance"""
    
    # Check if MMID exists
    cursor.execute("SELECT pin_hash, balance FROM users WHERE mmid = %s", (mmid,))
    user = cursor.fetchone()

    if not user:
        return {"status": "FAILED", "message": "Invalid MMID"}

    stored_pin_hash, balance = user  # Extract pin hash and balance from DB

    # Verify PIN
    if hashlib.sha256(pin.encode()).hexdigest() != stored_pin_hash:
        return {"status": "FAILED", "message": "Incorrect PIN"}

    # Check if user has enough balance
    if balance < amount:
        return {"status": "FAILED", "message": "Insufficient Balance"}

    return {"status": "SUCCESS", "message": "Transaction Verified"}

# Example Test Case
print(verify_transaction("BFBE7441403391C7", "1234", 500))
