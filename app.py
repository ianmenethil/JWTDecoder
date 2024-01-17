import os
import datetime
import base64
import secrets
import string
import json
from flask import Flask, request, render_template
import jwt
import binascii
import hashlib

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


def guess_hash(hash_string):
    hash_length = len(hash_string)
    hash_types = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
        # ... other hash lengths ...
    }
    return hash_types.get(hash_length, "Unknown")


def try_decode_base64(s):
    try:
        # Check if padding is correct for base64
        if len(s) % 4 == 0:
            return base64.b64decode(s).decode()
    except binascii.Error:
        pass
    return None


def try_decode_hex(s):
    try:
        return bytes.fromhex(s).decode()
    except ValueError:
        pass
    return None


@app.route('/', methods=['GET', 'POST'])
def decode_jwt():
    decoded = None
    if request.method == 'POST':
        jwt_token = request.form['jwt']
        try:
            # Decode JWT
            decoded_data = jwt.decode(jwt_token, options={"verify_signature": False})
            decoded = json.dumps(decoded_data, indent=4)
            if decoded:
                # Create output folder if it doesn't exist
                if not os.path.exists(OUTPUT_FOLDER):
                    os.makedirs(OUTPUT_FOLDER)

                # Create jwt folder inside output folder if it doesn't exist
                jwt_folder = os.path.join(OUTPUT_FOLDER, JWT_FOLDER)
                if not os.path.exists(jwt_folder):
                    os.makedirs(jwt_folder)

                # Generate unique filename with date
                current_date = datetime.datetime.now().strftime("%Y-%m-%d")
                jwt_filename = f"jwt_{current_date}.json"

                # Check if the file already exists, if so, append with _1, _2, etc.
                file_counter = 1
                while os.path.exists(os.path.join(jwt_folder, jwt_filename)):
                    jwt_filename = f"jwt_{current_date}_{file_counter}.json"
                    file_counter += 1

                # # Save the decoded JWT
                # with open(os.path.join(jwt_folder, jwt_filename), 'w', encoding='utf-8') as file:
                #     file.write(decoded)
                save_to_file(jwt_folder, jwt_filename, decoded)
            else:
                decoded = "Invalid JWT"

        except Exception as e:
            decoded = f"An error occurred: {e}"

    return render_template('template.html', decoded=decoded)


@app.route('/encryption', methods=['GET', 'POST'])
def handle_encryption():
    result = None
    if request.method == 'POST':
        input_data = request.form['input']
        try:
            # Determine if the input data is encoded or plain text
            try:
                # Try decoding as Base64
                decoded_data = base64.b64decode(input_data).decode()
                # If successful, it was encoded data
                result = f"Decoded (Base64): {decoded_data}"
            except Exception:
                # If an error occurs, it's likely plain text or a hash
                # Perform hashing
                sha1_result = hashlib.sha1(input_data.encode()).hexdigest()
                sha256_result = hashlib.sha256(input_data.encode()).hexdigest()
                sha3_256_result = hashlib.sha3_256(input_data.encode()).hexdigest()
                sha3_512_result = hashlib.sha3_512(input_data.encode()).hexdigest()
                result = f"SHA1: {sha1_result}, SHA256: {sha256_result}, SHA3-256: {sha3_256_result}, SHA3-512: {sha3_512_result}"
        except Exception as e:
            result = f"An error occurred: {e}"
    return render_template('template.html', encryption_result=result)


@app.route('/identify', methods=['GET', 'POST'])
def identify_string():
    result = None
    if request.method == 'POST':
        input_string = request.form['input_string']

        # Try decoding from Base64 and Hex
        base64_decoded = try_decode_base64(input_string)
        hex_decoded = try_decode_hex(input_string)

        # Guess hash type
        hash_type = guess_hash(input_string)

        result = {'base64': base64_decoded, 'hex': hex_decoded, 'hash_type': hash_type}

    return render_template('template.html', result=result)


@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if request.method == 'POST':
        characters = string.ascii_letters + string.digits + "~!@#$%^&*+-/.,\\{}[]();:?<>\'\"_"
        password = ''.join(secrets.choice(characters) for i in range(32))

        # Save the generated password
        with open('pwstory.txt', 'a', encoding='utf-8') as file:
            file.write(f"{password}\n")

        return render_template('template.html', generated_password=password)

    return render_template('template.html')


# @app.route('/base64', methods=['GET', 'POST'])
# def handle_base64():
#     result = None
#     if request.method == 'POST':
#         input_data = request.form['base64']
#         try:
#             # Try decoding Base64, if fails, encode the input
#             try:
#                 result = base64.b64decode(input_data).decode()
#             except Exception:
#                 result = base64.b64encode(input_data.encode()).decode()
#         except Exception as e:
#             result = f"An error occurred: {e}"
#     return render_template('template.html', base64_result=result)

# @app.route('/guess', methods=['GET', 'POST'])
# def guess_encoding_or_hash():
#     result = None
#     if request.method == 'POST':
#         input_string = request.form['input_string']

#         # Try decoding from Base64 and Hex
#         base64_decoded = try_decode_base64(input_string)
#         hex_decoded = try_decode_hex(input_string)

#         # Guess hash type
#         hash_type = guess_hash(input_string)

#         result = {'base64': base64_decoded, 'hex': hex_decoded, 'hash_type': hash_type}

#     return render_template('template.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
