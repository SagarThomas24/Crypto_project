from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import hashlib
import time
import base64
import qrcode
from flask_cors import CORS
import mysql.connector
from io import BytesIO
import os


app = Flask(__name__)
CORS(app) 
app.secret_key = 'super_secret_key' 

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="sagar333",
    database="blockchain_db"
)
cursor = db.cursor()

# Speck Cipher Implementation
class SpeckCipher:
    def __init__(self, key):
        self.block_size = 64     
        self.key_size = 128      
        self.rounds = 27         
        self.word_size = self.block_size >> 1 
        self.mod_mask = (2 ** self.word_size) - 1
        self.beta_shift = 3
        self.alpha_shift = 8
        self.key_schedule = [key & self.mod_mask]

        l_schedule = [(key >> (x * self.word_size)) & self.mod_mask 
                      for x in range(1, self.key_size // self.word_size)]
        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])

    def encrypt_round(self, x, y, k):
        rs_x = ((x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask
        add_sxy = (rs_x + y) & self.mod_mask
        new_x = k ^ add_sxy
        ls_y = ((y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask
        new_y = new_x ^ ls_y
        return new_x, new_y

    def encrypt(self, plaintext):
        b = (plaintext >> self.word_size) & self.mod_mask
        a = plaintext & self.mod_mask
        for k in self.key_schedule:
            b, a = self.encrypt_round(b, a, k)
        return (b << self.word_size) + a

cipher = SpeckCipher(0x12345678901234567890123456789012)

def generate_qr(vmid):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(vmid)
    qr.make(fit=True)

    img = qr.make_image(fill="black", back_color="white")

    # Ensure the 'static' folder exists
    static_folder = "static"
    if not os.path.exists(static_folder):
        os.makedirs(static_folder)

    qr_path = os.path.join(static_folder, "qr_code.png")
    img.save(qr_path)

    print("QR Code saved as static/qr_code.png")
    return qr_path
    
    

def generate_mid(merchant_name, password):
    timestamp = str(int(time.time()))  
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    raw_data = merchant_name + timestamp + password_hash
    final_hash = hashlib.sha256(raw_data.encode()).hexdigest()
    mid = final_hash[:16].upper()  
    return mid

def encrypt_speck(mid):
    """Encrypt MID using SpeckCipher."""
    mid_int = int(mid, 16)  
    vmid_int = cipher.encrypt(mid_int)  
    return hex(vmid_int)[2:].upper()  



@app.route("/")
def home():
    return render_template("index.html")

@app.route("/homepage")
def homepage():
    if 'name' in session:
        user_name = session['name']
        return render_template("a.html", name=user_name)  
    else:
        return redirect(url_for("home"))  

@app.route('/login', methods=['POST'])
def login():
    print("Login API Called") 
    data = request.json
    print("Received Data:", data)

    if not data:
        return jsonify({"error": "No data received"}), 400

    name = data.get('name')
    password = data.get('password')

    if not all([name, password]):
        return jsonify({"error": "Missing username or password"}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    sql = "SELECT mid FROM merchants WHERE name = %s AND password_hash = %s"
    cursor.execute(sql, (name, password_hash))
    result = cursor.fetchone()

    if result:
        mid = result[0]  
        session['name'] = name  

        print("Login Successful")
        return jsonify({
            "success": True, 
            "message": "Login successful!", 
            "redirect_url": "/homepage",
        }), 200
    else:
        print("Invalid Credentials")
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/qr_page", methods=["GET"])
def generate_qr_code():
    if "name" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    merchant_name = session["name"]
    sql = "SELECT mid FROM merchants WHERE name = %s"
    cursor.execute(sql, (merchant_name,))
    result = cursor.fetchone()
    cipher = SpeckCipher(0x12345678901234567890123456789012)
    if result:
        mid = result[0]
        vmid = encrypt_speck(mid)
    else:
        return jsonify({"error": "Merchant not found"}), 404
    
    qr_path = generate_qr(vmid)
    return render_template("qr_code.html", qr_code_path=qr_path)
    
    
    
    

@app.route("/check_balance", methods=["GET"])
def check_balance():
    if "name" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    merchant_name = session["name"]
    
    sql = "SELECT account_balance FROM merchants WHERE name = %s"
    cursor.execute(sql, (merchant_name,))
    result = cursor.fetchone()

    if result:
        return jsonify({"balance": result[0]})
    else:
        return jsonify({"error": "Merchant not found"}), 404
    


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/register_merchant', methods=['POST'])
def register_merchant():
    data = request.json
    name = data.get('name')
    password = data.get('password')
    balance = data.get('balance')
    ifsc_code = data.get('ifsc_code')

    if not all([name, password, balance, ifsc_code]):
        return jsonify({"error": "Missing data"}), 400

    mid = generate_mid(name, password)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    try:
        sql = "INSERT INTO merchants (name, password_hash, account_balance, ifsc_code, mid) VALUES (%s, %s, %s, %s, %s)"
        values = (name, password_hash, balance, ifsc_code, mid)
        cursor.execute(sql, values)
        db.commit()
        return jsonify({"message": f"Merchant '{name}' registered successfully!", "MID": mid})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
