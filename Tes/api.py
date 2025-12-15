# api.py
from flask import Flask, request, jsonify
from cipher.AES import AESCipher, parse_key
from cipher.RSA import RSACipher
import os

app = Flask(__name__)

aes = AESCipher()
rsa = RSACipher()

# ======================================================
# AES
# ======================================================
@app.route("/api/aes/encrypt", methods=["POST"])
def aes_encrypt():
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400

    file = request.files["file"]
    key = request.form.get("key")
    output_path = request.form.get("output_path")

    if not key:
        return jsonify({"error": "key required"}), 400

    data = file.read()

    try:
        parse_key(key)
        cipher_bytes = aes.encrypt_bytes_with_key(data, key)

        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(cipher_bytes)

        return jsonify({"message": "AES encrypted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/aes/decrypt", methods=["POST"])
def aes_decrypt():
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400

    file = request.files["file"]
    key = request.form.get("key")
    output_path = request.form.get("output_path")

    if not key:
        return jsonify({"error": "key required"}), 400

    data = file.read()

    try:
        parse_key(key)
        plain_bytes = aes.decrypt_bytes_with_key(data, key)

        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(plain_bytes)

        return jsonify({"message": "AES decrypted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ======================================================
# RSA
# ======================================================
@app.route("/api/rsa/generate", methods=["GET"])
def rsa_generate():
     try:
        p = request.args.get("p", type=int)
        q = request.args.get("q", type=int)

        keys = rsa.generate_keys(p, q)

        return jsonify({
            "p": keys["p"],
            "q": keys["q"],
            "n": keys["n"],
            "phi": keys["phi"],
            "public_key": keys["public_key"],
            "private_key": keys["private_key"]
        }), 200

     except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    j = request.get_json()
    message = j.get("message")
    pub = j.get("public_key")

    if not message or not pub:
        return jsonify({"error": "message & public_key required"}), 400

    e = int(pub["e"])
    n = int(pub["n"])

    cipher = rsa.encrypt(message, (e, n))
    return jsonify({"encrypted_hex": cipher}), 200


@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    j = request.get_json()
    cipher_text = j.get("cipher_hex")
    priv = j.get("private_key")

    if not cipher_text or not priv:
        return jsonify({"error": "cipher & private_key required"}), 400

    d = int(priv["d"])
    n = int(priv["n"])

    plain = rsa.decrypt(cipher_text, (d, n))
    return jsonify({"plain": plain}), 200





if __name__ == "__main__":
     app.run(host="0.0.0.0", port=5000, debug=True)
