from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)

# ================= DATABASE MODELS =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    algorithm = db.Column(db.String(50))
    ciphertext = db.Column(db.Text)
    iv = db.Column(db.String(100), nullable=True)

#db.create_all()

# ================= HELPER FUNCTIONS =================
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def aes_encrypt(plain_text, key):
    key_bytes = key.encode('utf-8')
    cipher = AES.new(pad(key_bytes, 16), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), 16))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return {'iv': iv, 'ciphertext': ct}

def aes_decrypt(ciphertext, iv, key):
    try:
        key_bytes = key.encode('utf-8')
        iv = base64.b64decode(iv)
        cipher = AES.new(pad(key_bytes, 16), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 16)
        return pt.decode('utf-8')
    except Exception:
        return None

# ================= AUTH ROUTES =================
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists'}), 400

    hashed = generate_password_hash(password)
    new_user = User(username=username, password=hashed)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registration successful'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = user.id
    return jsonify({'message': 'Login successful', 'user': username})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'})

# ================= ENCRYPTION ROUTES =================
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    text = data.get('text')
    algorithm = data.get('algorithm')
    key = data.get('key', '')
    shift = int(data.get('shift', 3))

    if not text or not algorithm:
        return jsonify({'error': 'Missing fields'}), 400

    result = None
    iv = None
    if algorithm == 'caesar':
        result = caesar_cipher(text, shift)
    elif algorithm == 'base64':
        result = base64.b64encode(text.encode()).decode()
    elif algorithm == 'aes':
        enc = aes_encrypt(text, key)
        result = enc['ciphertext']
        iv = enc['iv']

    # Save encrypted message to DB
    new_msg = Message(user_id=session['user_id'], algorithm=algorithm, ciphertext=result, iv=iv)
    db.session.add(new_msg)
    db.session.commit()

    return jsonify({'result': result, 'iv': iv})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    text = data.get('text')
    algorithm = data.get('algorithm')
    key = data.get('key', '')
    shift = int(data.get('shift', 3))
    iv = data.get('iv', '')

    if not text or not algorithm:
        return jsonify({'error': 'Missing fields'}), 400

    if algorithm == 'caesar':
        result = caesar_cipher(text, -shift)
    elif algorithm == 'base64':
        result = base64.b64decode(text.encode()).decode()
    elif algorithm == 'aes':
        result = aes_decrypt(text, iv, key)
    else:
        result = 'Unknown algorithm'

    return jsonify({'result': result})

@app.route('/messages', methods=['GET'])
def get_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    messages = Message.query.filter_by(user_id=session['user_id']).all()
    data = [
        {'id': m.id, 'algorithm': m.algorithm, 'ciphertext': m.ciphertext, 'iv': m.iv}
        for m in messages
    ]
    return jsonify(data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
