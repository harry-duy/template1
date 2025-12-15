# main_aes.py
import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QMessageBox, QFileDialog
)
from UI.aes import Ui_MainWindow
import requests


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Gán sự kiện
        self.ui.btnBrowseInput.clicked.connect(self.browse_input)
        self.ui.btnBrowseOutput.clicked.connect(self.browse_output)
        self.ui.btnEncrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.call_api_decrypt)

        # ====== Save & Load key ======
        self.ui.btnSaveKey.clicked.connect(self.save_key_to_file)
        self.ui.btnLoadKey.clicked.connect(self.load_key_from_file)

    # ============= BROWSE INPUT ==============
    def browse_input(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose input file")
        if file_path:
            self.ui.txtInput.setText(file_path)

    # ============= BROWSE OUTPUT =============
    def browse_output(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Choose output file")
        if file_path:
            self.ui.txtOutput.setText(file_path)

    # ============= SAVE KEY ==================
    def save_key_to_file(self):
        key = self.ui.txtKey.text().strip()
        if not key:
            QMessageBox.warning(self, "Error", "Key is empty!")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save key to file", filter="Key Files (*.key)")
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(key)
                QMessageBox.information(self, "Success", "Key saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # ============= LOAD KEY ===================
    def load_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load key file", filter="Key Files (*.key)")
        if file_path:
            try:
                with open(file_path, "r") as f:
                    key = f.read().strip()
                self.ui.txtKey.setText(key)
                QMessageBox.information(self, "Success", "Key loaded!")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # ============= CALL API ENCRYPT ===========
    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/aes/encrypt"

        input_file = self.ui.txtInput.text().strip()
        output_file = self.ui.txtOutput.text().strip()
        key = self.ui.txtKey.text().strip()

        if not input_file or not os.path.exists(input_file):
            QMessageBox.warning(self, "Error", "Input file does not exist!")
            return

        if not key:
            QMessageBox.warning(self, "Error", "Key is required!")
            return

        files = {"file": open(input_file, "rb")}
        data = {"key": key, "output_path": output_file}

        try:
            res = requests.post(url, files=files, data=data)
            if res.status_code == 200:
                QMessageBox.information(self, "Success", "File encrypted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"API Error: {res.status_code}\n{res.text}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ============= CALL API DECRYPT ===========
    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/aes/decrypt"

        input_file = self.ui.txtInput.text().strip()
        output_file = self.ui.txtOutput.text().strip()
        key = self.ui.txtKey.text().strip()

        if not input_file or not os.path.exists(input_file):
            QMessageBox.warning(self, "Error", "Input file does not exist!")
            return

        if not key:
            QMessageBox.warning(self, "Error", "Key is required!")
            return

        files = {"file": open(input_file, "rb")}
        data = {"key": key, "output_path": output_file}

        try:
            res = requests.post(url, files=files, data=data)
            if res.status_code == 200:
                QMessageBox.information(self, "Success", "File decrypted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"API Error: {res.status_code}\n{res.text}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())
