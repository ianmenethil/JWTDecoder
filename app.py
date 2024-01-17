import os
import datetime
import base64
import secrets
import string
import json
import binascii
import hashlib
from flask import Flask, request, render_template
import jwt

app = Flask(__name__)

OUTPUT_FOLDER = 'output'
JWT_FOLDER = 'jwt'


def save_to_file(folder, filename, data, mode='w'):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, filename)
    with open(file_path, mode, encoding='utf-8') as file:
        file.write(data)
    return file_path


def guess_hash(hash_string) -> str:
    hash_length = len(hash_string)
    hash_types = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
    }
    return hash_types.get(hash_length, "Unknown")


def try_decode_base64(s) -> str | None:
    try:
        if len(s) % 4 == 0:
            return base64.b64decode(s).decode()
    except binascii.Error:
        pass
    return None


def try_decode_hex(s) -> str | None:
    try:
        return bytes.fromhex(s).decode()
    except ValueError:
        pass
    return None


@app.route('/', methods=['GET', 'POST'])
def decode_jwt() -> str:
    decoded = None
    if request.method == 'POST':
        jwt_token = request.form['jwt']
        try:
            decoded_data = jwt.decode(jwt_token, options={"verify_signature": False})
            decoded = json.dumps(decoded_data, indent=4)
            if decoded:
                if not os.path.exists(OUTPUT_FOLDER):
                    os.makedirs(OUTPUT_FOLDER)

                jwt_folder = os.path.join(OUTPUT_FOLDER, JWT_FOLDER)
                if not os.path.exists(jwt_folder):
                    os.makedirs(jwt_folder)

                current_date = datetime.datetime.now().strftime("%Y-%m-%d")
                jwt_filename = f"jwt_{current_date}.json"

                file_counter = 1
                while os.path.exists(os.path.join(jwt_folder, jwt_filename)):
                    jwt_filename = f"jwt_{current_date}_{file_counter}.json"
                    file_counter += 1

                save_to_file(jwt_folder, jwt_filename, decoded)
            else:
                decoded = "Invalid JWT"

        except Exception as e:
            decoded = f"An error occurred: {e}"

    return render_template('template.html', decoded=decoded)


@app.route('/encryption', methods=['GET', 'POST'])
def handle_encryption() -> str:
    result = None
    if request.method == 'POST':
        input_data = request.form['input']
        try:
            try:
                decoded_data = base64.b64decode(input_data).decode()
                result = f"Decoded (Base64): {decoded_data}"
            except Exception:
                sha1_result = hashlib.sha1(input_data.encode()).hexdigest()
                sha256_result = hashlib.sha256(input_data.encode()).hexdigest()
                sha3_256_result = hashlib.sha3_256(input_data.encode()).hexdigest()
                sha3_512_result = hashlib.sha3_512(input_data.encode()).hexdigest()
                result = f"SHA1: {sha1_result}, SHA256: {sha256_result}, SHA3-256: {sha3_256_result}, SHA3-512: {sha3_512_result}"
        except Exception as e:
            result = f"An error occurred: {e}"
    return render_template('template.html', encryption_result=result)


@app.route('/identify', methods=['GET', 'POST'])
def identify_string() -> str:
    result = None
    if request.method == 'POST':
        input_string = request.form['input_string']

        base64_decoded = try_decode_base64(input_string)
        hex_decoded = try_decode_hex(input_string)

        hash_type = guess_hash(input_string)

        result = {'base64': base64_decoded, 'hex': hex_decoded, 'hash_type': hash_type}

    return render_template('template.html', result=result)


@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password() -> str:
    if request.method == 'POST':
        characters = string.ascii_letters + string.digits + "~!@#$%^&*+-/.,\\{}[]();:?<>\'\"_"
        password = ''.join(secrets.choice(characters) for i in range(32))

        with open('pwstory.txt', 'a', encoding='utf-8') as file:
            file.write(f"{password}\n")

        return render_template('template.html', generated_password=password)

    return render_template('template.html')


if __name__ == '__main__':
    app.run(debug=True)
