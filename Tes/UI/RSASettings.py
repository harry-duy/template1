# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_RSAWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("RSAWindow")
        MainWindow.resize(520, 380)

        self.centralwidget = QtWidgets.QWidget(MainWindow)

        # ===== TITLE =====
        self.labelTitle = QtWidgets.QLabel(self.centralwidget)
        self.labelTitle.setGeometry(QtCore.QRect(110, 10, 350, 40))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.labelTitle.setFont(font)
        self.labelTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.labelTitle.setText("RSA – Key Generator")

        # ===== INPUT p =====
        self.labelP = QtWidgets.QLabel(self.centralwidget)
        self.labelP.setText("Prime p:")
        self.labelP.setGeometry(40, 70, 100, 25)

        self.txtP = QtWidgets.QLineEdit(self.centralwidget)
        self.txtP.setGeometry(150, 70, 200, 25)
        self.txtP.setPlaceholderText("Ví dụ: 61")

        # ===== INPUT q =====
        self.labelQ = QtWidgets.QLabel(self.centralwidget)
        self.labelQ.setText("Prime q:")
        self.labelQ.setGeometry(40, 110, 100, 25)

        self.txtQ = QtWidgets.QLineEdit(self.centralwidget)
        self.txtQ.setGeometry(150, 110, 200, 25)
        self.txtQ.setPlaceholderText("Ví dụ: 53")

        # ===== BUTTON =====
        self.btnGenerate = QtWidgets.QPushButton(self.centralwidget)
        self.btnGenerate.setText("Generate Keys")
        self.btnGenerate.setGeometry(150, 155, 200, 35)
        self.btnGenerate.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

        # ===== OUTPUT n =====
        self.txtN = QtWidgets.QLineEdit(self.centralwidget)
        self.txtN.setGeometry(150, 205, 320, 25)
        self.txtN.setPlaceholderText("n = p × q")
        self.txtN.setReadOnly(True)

        # ===== OUTPUT φ(n) =====
        self.txtPhi = QtWidgets.QLineEdit(self.centralwidget)
        self.txtPhi.setGeometry(150, 240, 320, 25)
        self.txtPhi.setPlaceholderText("φ(n) = (p − 1)(q − 1)")
        self.txtPhi.setReadOnly(True)

        # ===== OUTPUT PUBLIC KEY =====
        self.txtPublic = QtWidgets.QLineEdit(self.centralwidget)
        self.txtPublic.setGeometry(150, 275, 320, 25)
        self.txtPublic.setPlaceholderText("Public key (e, n)")
        self.txtPublic.setReadOnly(True)

        # ===== OUTPUT PRIVATE KEY =====
        self.txtPrivate = QtWidgets.QLineEdit(self.centralwidget)
        self.txtPrivate.setGeometry(150, 310, 320, 25)
        self.txtPrivate.setPlaceholderText("Private key (d, n)")
        self.txtPrivate.setReadOnly(True)

        MainWindow.setCentralWidget(self.centralwidget)

        # ===== TAB ORDER =====
        MainWindow.setTabOrder(self.txtP, self.txtQ)
        MainWindow.setTabOrder(self.txtQ, self.btnGenerate)
