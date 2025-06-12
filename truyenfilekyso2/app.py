# app.py
from flask import Flask, render_template, request, jsonify
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('sender.html')

@app.route('/receiver')
def receiver():
    return render_template('receiver.html')

@app.route('/sign', methods=['POST'])
def sign_file():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(filepath)

    with open(filepath, 'rb') as f:
        data = f.read()

    # Tạo khóa RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Ký dữ liệu
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Export khóa công khai (PEM)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Export khóa bí mật (PEM không mã hóa)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # hoặc PKCS8
        encryption_algorithm=serialization.NoEncryption()
    )

    # Lưu các file: chữ ký, public key và private key
    sig_path = filepath + ".sig"
    pub_path = filepath + ".pub"
    pri_path = filepath + ".pem"  # lưu khóa bí mật

    with open(sig_path, "wb") as f:
        f.write(signature)

    with open(pub_path, "wb") as f:
        f.write(public_pem)

    with open(pri_path, "wb") as f:
        f.write(private_pem)

    return jsonify({
        'signature': base64.b64encode(signature).decode(),
        'public_key': base64.b64encode(public_pem).decode()
    })


@app.route('/verify', methods=['POST'])
def verify_signature():
    uploaded_file = request.files['file']
    data = uploaded_file.read()
    signature = base64.b64decode(request.form['signature'])
    public_key_b64 = base64.b64decode(request.form['public_key'])

    public_key = serialization.load_pem_public_key(
        public_key_b64,
        backend=default_backend()
    )

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False})

app.run(host="0.0.0.0", port=5000, debug=True)