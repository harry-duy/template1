# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets
from UI.RSASettings import Ui_RSAWindow


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(650, 500)
        self.centralwidget = QtWidgets.QWidget(MainWindow)

        # ===================== TITLE =====================
        self.labelTitle = QtWidgets.QLabel(self.centralwidget)
        self.labelTitle.setGeometry(QtCore.QRect(130, 10, 400, 40))
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        self.labelTitle.setFont(font)
        self.labelTitle.setText("Encryption / Decryption Tool")

        # ================= ALGORITHM BOX =================
        self.groupAlgo = QtWidgets.QGroupBox(self.centralwidget)
        self.groupAlgo.setGeometry(QtCore.QRect(40, 70, 200, 160))
        self.groupAlgo.setTitle("Algorithm")

        # AES
        self.radioAES = QtWidgets.QRadioButton(self.groupAlgo)
        self.radioAES.setGeometry(QtCore.QRect(20, 30, 100, 20))
        self.radioAES.setChecked(True)
        self.radioAES.setText("AES")

        # DES
        self.radioDES = QtWidgets.QRadioButton(self.groupAlgo)
        self.radioDES.setGeometry(QtCore.QRect(20, 60, 100, 20))
        self.radioDES.setText("DES")

        # Triple DES
        self.radioTripleDES = QtWidgets.QRadioButton(self.groupAlgo)
        self.radioTripleDES.setGeometry(QtCore.QRect(20, 90, 120, 20))
        self.radioTripleDES.setText("Triple DES")

        # RSA
        self.radioRSA = QtWidgets.QRadioButton(self.groupAlgo)
        self.radioRSA.setGeometry(QtCore.QRect(20, 120, 100, 20))
        self.radioRSA.setText("RSA")

        # Khi chọn RSA → mở cửa sổ RSA
        self.radioRSA.toggled.connect(self.open_rsa_settings)

        # ================= INPUT FILE =================
        self.labelInput = QtWidgets.QLabel(self.centralwidget)
        self.labelInput.setGeometry(QtCore.QRect(270, 80, 100, 20))
        self.labelInput.setText("Input File:")

        self.txtInput = QtWidgets.QLineEdit(self.centralwidget)
        self.txtInput.setGeometry(QtCore.QRect(350, 80, 200, 25))

        self.btnBrowseInput = QtWidgets.QPushButton(self.centralwidget)
        self.btnBrowseInput.setGeometry(QtCore.QRect(560, 80, 40, 25))
        self.btnBrowseInput.setText("...")

        # ================= OUTPUT FILE =================
        self.labelOutput = QtWidgets.QLabel(self.centralwidget)
        self.labelOutput.setGeometry(QtCore.QRect(270, 120, 100, 20))
        self.labelOutput.setText("Output File:")

        self.txtOutput = QtWidgets.QLineEdit(self.centralwidget)
        self.txtOutput.setGeometry(QtCore.QRect(350, 120, 200, 25))

        self.btnBrowseOutput = QtWidgets.QPushButton(self.centralwidget)
        self.btnBrowseOutput.setGeometry(QtCore.QRect(560, 120, 40, 25))
        self.btnBrowseOutput.setText("...")

        # ================= KEY FIELD =================
        self.labelKey = QtWidgets.QLabel(self.centralwidget)
        self.labelKey.setGeometry(QtCore.QRect(270, 160, 100, 20))
        self.labelKey.setText("Key:")

        self.txtKey = QtWidgets.QLineEdit(self.centralwidget)
        self.txtKey.setGeometry(QtCore.QRect(350, 160, 200, 25))

        # ----- Nút Load key -----
        self.btnLoadKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnLoadKey.setGeometry(QtCore.QRect(350, 195, 95, 28))
        self.btnLoadKey.setText("Load Key")

        # ----- Nút Save key -----
        self.btnSaveKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnSaveKey.setGeometry(QtCore.QRect(455, 195, 95, 28))
        self.btnSaveKey.setText("Save Key")

        # ================= BUTTONS =================
        self.btnEncrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btnEncrypt.setGeometry(QtCore.QRect(280, 260, 120, 35))
        self.btnEncrypt.setText("Encrypt")

        self.btnDecrypt = QtWidgets.QPushButton(self.centralwidget)
        self.btnDecrypt.setGeometry(QtCore.QRect(420, 260, 120, 35))
        self.btnDecrypt.setText("Decrypt")

        MainWindow.setCentralWidget(self.centralwidget)

    # =============================================
    #   MỞ GIAO DIỆN THIẾT LẬP RSA
    # =============================================
    def open_rsa_settings(self):
        if self.radioRSA.isChecked():
            self.rsawin = QtWidgets.QMainWindow()
            self.rsaui = Ui_RSAWindow()
            self.rsaui.setupUi(self.rsawin)
            self.rsawin.show()