
from flask import Flask, request, render_template, flash
from encryption import encrypt_message, decrypt_message, generate_key
from twilio_service import send_otp

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace this with your actual secret key

otp_store = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    phone_number = request.form['phone_number']
    key = generate_key()
    encrypted_message = encrypt_message(message, key)
    otp = key.hex()
    otp_store[phone_number] = otp
    send_otp(phone_number, otp)  # Send OTP via SMS
    flash('Message encrypted and OTP sent to the provided phone number.')
    return render_template('index.html', encrypted_message=encrypted_message.hex())

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message = bytes.fromhex(request.form['encrypted_message'])
    otp = request.form['otp']
    phone_number = request.form['phone_number']
    if phone_number in otp_store and otp_store[phone_number] == otp:
        key = bytes.fromhex(otp)
        decrypted_message = decrypt_message(encrypted_message, key)
        flash('Message decrypted successfully.')
        return render_template('index.html', decrypted_message=decrypted_message)
    else:
        flash('Invalid OTP or phone number.')
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
