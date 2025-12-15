# main_rsa.py
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from UI.RSASettings import Ui_RSAWindow
import requests


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # DÙNG ĐÚNG UI (KHÔNG PHẢI Ui_MainWindow)
        self.ui = Ui_RSAWindow()
        self.ui.setupUi(self)

        # Gán sự kiện nút Generate Keys
        self.ui.btnGenerate.clicked.connect(self.call_api_generate_keys)

        # Gán Encrypt / Decrypt nếu có
        if hasattr(self.ui, "btnEncrypt"):
            self.ui.btnEncrypt.clicked.connect(self.call_api_encrypt)

        if hasattr(self.ui, "btnDecrypt"):
            self.ui.btnDecrypt.clicked.connect(self.call_api_decrypt)

        # Sign / Verify nếu giao diện có
        if hasattr(self.ui, "btn_sign"):
            self.ui.btn_sign.clicked.connect(self.call_api_sign)

        if hasattr(self.ui, "btn_verify"):
            self.ui.btn_verify.clicked.connect(self.call_api_verify)

    # ============================================================
    # 1) Generate RSA Keys
    # ============================================================
    def call_api_generate_keys(self):
        url = "http://127.0.0.1:5000/api/rsa/generate"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                data = r.json()
                pub = data["public_key"]
                priv = data["private_key"]

                # Hiển thị lên UI
                self.ui.txtN.setText(str(pub["n"]))
                self.ui.txtPhi.setText("Không cần API trả về")

                self.ui.txtPublic.setText(f"({pub['e']}, {pub['n']})")
                self.ui.txtPrivate.setText(f"({priv['d']}, {priv['n']})")

                QMessageBox.information(self, "Success", "RSA Keys Generated!")
            else:
                QMessageBox.warning(self, "Error", r.text)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ============================================================
    # 2) Encrypt RSA
    # ============================================================
    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/encrypt"
        message = self.ui.txtPlain.toPlainText()

        try:
            e = int(self.ui.txtE.text())
            n = int(self.ui.txtN.text())
        except:
            QMessageBox.warning(self, "Error", "Bạn phải nhập e và n hợp lệ!")
            return

        data = {"data": message, "public_key": [e, n]}

        try:
            r = requests.post(url, json=data)
            if r.status_code == 200:
                cipher = r.json()["cipher"]
                self.ui.txtCipher.setPlainText(cipher)
                QMessageBox.information(self, "Success", "Encrypted!")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ============================================================
    # 3) Decrypt RSA
    # ============================================================
    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/decrypt"
        cipher = self.ui.txtCipher.toPlainText()

        try:
            d = int(self.ui.txtD.text())
            n = int(self.ui.txtN.text())
        except:
            QMessageBox.warning(self, "Error", "Bạn phải nhập d và n hợp lệ!")
            return

        data = {"cipher": cipher, "private_key": [d, n]}

        try:
            r = requests.post(url, json=data)
            if r.status_code == 200:
                plain = r.json()["plain"]
                self.ui.txtPlain.setPlainText(plain)
                QMessageBox.information(self, "Success", "Decrypted!")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ============================================================
    # 4) Sign
    # ============================================================
    def call_api_sign(self):
        url = "http://127.0.0.1:5000/api/rsa/sign"
        message = self.ui.txtInfo.toPlainText()

        try:
            d = int(self.ui.txtD.text())
            n = int(self.ui.txtN.text())
        except:
            QMessageBox.warning(self, "Error", "Bạn phải nhập private key!")
            return

        try:
            r = requests.post(url, json={"message": message, "private_key": [d, n]})
            if r.status_code == 200:
                sig = r.json()["signature"]
                self.ui.txtSign.setPlainText(sig)
                QMessageBox.information(self, "Success", "Signed!")
            else:
                QMessageBox.warning(self, "Error", r.text)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ============================================================
    # 5) Verify
    # ============================================================
    def call_api_verify(self):
        url = "http://127.0.0.1:5000/api/rsa/verify"
        message = self.ui.txtInfo.toPlainText()
        signature = self.ui.txtSign.toPlainText()

        try:
            e = int(self.ui.txtE.text())
            n = int(self.ui.txtN.text())
        except:
            QMessageBox.warning(self, "Error", "Bạn phải nhập public key!")
            return

        try:
            r = requests.post(url, json={
                "message": message,
                "signature": signature,
                "public_key": [e, n]
            })
            if r.status_code == 200:
                ok = r.json()["is_verified"]
                QMessageBox.information(self, "Verify", "✔ Valid" if ok else "❌ Invalid")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MyApp()
    w.show()
    sys.exit(app.exec_())
