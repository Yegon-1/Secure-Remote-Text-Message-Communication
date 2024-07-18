from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import os
from twilio.rest import Client

app = Flask(__name__)

# Twilio configuration
TWILIO_ACCOUNT_SID = 'ACCOUNT SID HERE'
TWILIO_AUTH_TOKEN = 'AUTH TOKEN HERE'
TWILIO_PHONE_NUMBER = 'twilio PHONE NUMBER HERE'

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Generate a 16-byte (128-bit) AES key
AES_KEY = os.urandom(16)

def send_sms(phone_number, message):
    message = client.messages.create(
        body=message,
        from_=TWILIO_PHONE_NUMBER,
        to=phone_number
    )

def pad(data, block_size):
    pad_length = block_size - len(data) % block_size
    padding = bytes([pad_length] * pad_length)
    return data + padding

def unpad(data):
    return data[:-data[-1]]

def encrypt_message(message):
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted_message).decode(), base64.b64encode(iv).decode()

def decrypt_message(encrypted_message, iv):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        iv = base64.b64decode(iv)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message)).decode()
        return decrypted_message
    except (ValueError, KeyError):
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data['message']
    phone_number = data['phone_number']
    encrypted_message, iv = encrypt_message(message)
    full_message = f"Encrypted Message: {encrypted_message}, Special code(IV): {iv}"

    send_sms(phone_number, full_message)

    return jsonify({'status': 'Message and special code sent!'})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_message = data['encryptedMessage']
    iv = data['specialCode']
    decrypted_message = decrypt_message(encrypted_message, iv)
    
    if decrypted_message:
        return jsonify({'status': 'Decryption Successful', 'decryptedMessage': decrypted_message})
    else:
        return jsonify({'status': 'Decryption failed. Invalid special code (IV) or encrypted message.'})

if __name__ == '__main__':
    app.run(debug=True)
