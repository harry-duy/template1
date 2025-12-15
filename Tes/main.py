# main.py
import sys
import os
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow,
    QMessageBox, QFileDialog
)

from UI.aes import Ui_MainWindow
from UI.RSASettings import Ui_RSAWindow


API_URL = "http://127.0.0.1:5000"


# ============================================================
# MAIN APP (AES + RSA)
# ============================================================
class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # ===== FILE =====
        self.ui.btnBrowseInput.clicked.connect(self.browse_input)
        self.ui.btnBrowseOutput.clicked.connect(self.browse_output)

        # ===== ACTION =====
        self.ui.btnEncrypt.clicked.connect(self.encrypt)
        self.ui.btnDecrypt.clicked.connect(self.decrypt)

        # ===== KEY =====
        self.ui.btnSaveKey.clicked.connect(self.save_key)
        self.ui.btnLoadKey.clicked.connect(self.load_key)

        # ===== RSA =====
        self.ui.radioRSA.toggled.connect(self.open_rsa_window)
        self.rsa_window = None

    # ========================================================
    # FILE
    # ========================================================
    def browse_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose input file")
        if path:
            self.ui.txtInput.setText(path)

    def browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Choose output file")
        if path:
            self.ui.txtOutput.setText(path)

    def read_input_text(self):
        with open(self.ui.txtInput.text(), "r", encoding="utf-8") as f:
            return f.read()

    def write_output_text(self, content):
        with open(self.ui.txtOutput.text(), "w", encoding="utf-8") as f:
            f.write(content)

    # ========================================================
    # SWITCH
    # ========================================================
    def encrypt(self):
        if self.ui.radioAES.isChecked():
            self.aes_encrypt()
        elif self.ui.radioRSA.isChecked():
            self.rsa_encrypt()

    def decrypt(self):
        if self.ui.radioAES.isChecked():
            self.aes_decrypt()
        elif self.ui.radioRSA.isChecked():
            self.rsa_decrypt()

    # ========================================================
    # AES
    # ========================================================
    def aes_encrypt(self):
        self.call_api_file_crypto("/api/aes/encrypt")

    def aes_decrypt(self):
        self.call_api_file_crypto("/api/aes/decrypt")

    def call_api_file_crypto(self, endpoint):
        infile = self.ui.txtInput.text().strip()
        outfile = self.ui.txtOutput.text().strip()
        key = self.ui.txtKey.text().strip()

        if not os.path.exists(infile):
            QMessageBox.warning(self, "Error", "Input file not found")
            return

        if not key:
            QMessageBox.warning(self, "Error", "AES key required")
            return

        url = API_URL + endpoint
        files = {"file": open(infile, "rb")}
        data = {"key": key, "output_path": outfile}

        try:
            r = requests.post(url, files=files, data=data)
            if r.status_code == 200:
                QMessageBox.information(self, "Success", "AES Done!")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ========================================================
    # RSA
    # ========================================================
    def rsa_encrypt(self):
        try:
            e, n = map(int, self.ui.txtKey.text().split(","))
        except:
            QMessageBox.warning(self, "Error", "RSA public key phải dạng: e,n")
            return

        payload = {
            "message": self.read_input_text(),
            "public_key": {"e": e, "n": n}
        }

        try:
            r = requests.post(API_URL + "/api/rsa/encrypt", json=payload)
            if r.status_code == 200:
                self.write_output_text(r.json()["encrypted_hex"])
                QMessageBox.information(self, "OK", "RSA Encrypt thành công")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def rsa_decrypt(self):
        try:
            d, n = map(int, self.ui.txtKey.text().split(","))
        except:
            QMessageBox.warning(self, "Error", "RSA private key phải dạng: d,n")
            return

        payload = {
            "cipher_hex": self.read_input_text(),
            "private_key": {"d": d, "n": n}
        }

        try:
            r = requests.post(API_URL + "/api/rsa/decrypt", json=payload)
            if r.status_code == 200:
                self.write_output_text(r.json()["plain"])
                QMessageBox.information(self, "OK", "RSA Decrypt thành công")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ========================================================
    # KEY
    # ========================================================
    def save_key(self):
        key = self.ui.txtKey.text().strip()
        if not key:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save key", filter="*.key")
        if path:
            with open(path, "w") as f:
                f.write(key)

    def load_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load key", filter="*.key")
        if path:
            with open(path, "r") as f:
                self.ui.txtKey.setText(f.read().strip())

    # ========================================================
    # RSA WINDOW
    # ========================================================
    def open_rsa_window(self):
        if not self.ui.radioRSA.isChecked():
            return
        if self.rsa_window is None:
            self.rsa_window = RSAWindow()
        self.rsa_window.show()


# ============================================================
# RSA WINDOW
# ============================================================
class RSAWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_RSAWindow()
        self.ui.setupUi(self)
        self.ui.btnGenerate.clicked.connect(self.generate)

    def generate(self):
        p = self.ui.txtP.text().strip()
        q = self.ui.txtQ.text().strip()

        if not p or not q:
            QMessageBox.warning(self, "Error", "Nhập p và q")
            return

        url = f"{API_URL}/api/rsa/generate?p={p}&q={q}"

        try:
            r = requests.get(url)
            if r.status_code == 200:
                data = r.json()
                pub = data["public_key"]
                priv = data["private_key"]

                self.ui.txtN.setText(str(pub["n"]))
                self.ui.txtPhi.setText("Auto")
                self.ui.txtPublic.setText(f"{pub['e']},{pub['n']}")
                self.ui.txtPrivate.setText(f"{priv['d']},{priv['n']}")
            else:
                QMessageBox.warning(self, "Error", r.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainApp()
    w.show()
    sys.exit(app.exec_())
