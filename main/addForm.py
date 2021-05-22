# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'addData.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        Form.setObjectName("Form")
        Form.resize(400, 300)
        self.frame = QtWidgets.QFrame(Form)
        self.frame.setGeometry(QtCore.QRect(0, 10, 401, 281))
        self.frame.setStyleSheet("QFrame{background-color: blac;\n"
"border: 5px solid white;\n"
"border-radius: 10px\n"
"}\n"
"QLabel{ \n"
"color: white;\n"
"border: 0}\n"
"\n"
"QLineEdit {\n"
"    background-color: rgba(0, 0, 0, 50);\n"
"    color: white;\n"
"    border: 2px solid white;\n"
"    border-radius: 2px\n"
"}\n"
"QPushButton {\n"
"    background-color: black;\n"
"    color: white;\n"
"    border: 3px solid white;\n"
"    border-radius: 5px}"
"""QLabel#title {
    font: 14pt "MV Boli" bold;
    background-color: rgba(255, 255, 255, 150);
    color: black;
    text-align: center
    }"""
)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.frame)
        self.verticalLayout.setObjectName("verticalLayout")
        self.title = QtWidgets.QLabel(self.frame)
        self.title.setMinimumSize(QtCore.QSize(0, 25))
        self.title.setMaximumSize(QtCore.QSize(16777215, 24))
        self.title.setStyleSheet("border: 2px solid white")
        self.title.setText("")
        self.title.setObjectName("title")
        self.verticalLayout.addWidget(self.title)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setStyleSheet("")
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.email = QtWidgets.QLineEdit(self.frame)
        self.email.setStyleSheet("")
        self.email.setObjectName("email")
        self.horizontalLayout.addWidget(self.email)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.frame)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.password = QtWidgets.QLineEdit(self.frame)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setObjectName("password")
        self.horizontalLayout_2.addWidget(self.password)
        self.hide_show = QtWidgets.QPushButton(self.frame)
        self.hide_show.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("graphic/show_pass.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        icon.addPixmap(QtGui.QPixmap("graphic/hide_pass.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        icon.addPixmap(QtGui.QPixmap("graphic/show_pass.png"), QtGui.QIcon.Disabled, QtGui.QIcon.Off)
        icon.addPixmap(QtGui.QPixmap("graphic/hide_pass.png"), QtGui.QIcon.Disabled, QtGui.QIcon.On)
        icon.addPixmap(QtGui.QPixmap("graphic/show_pass.png"), QtGui.QIcon.Active, QtGui.QIcon.Off)
        icon.addPixmap(QtGui.QPixmap("graphic/hide_pass.png"), QtGui.QIcon.Active, QtGui.QIcon.On)
        icon.addPixmap(QtGui.QPixmap("graphic/show_pass.png"), QtGui.QIcon.Selected, QtGui.QIcon.Off)
        icon.addPixmap(QtGui.QPixmap("graphic/hide_pass.png"), QtGui.QIcon.Selected, QtGui.QIcon.On)
        self.hide_show.setIcon(icon)
        self.hide_show.setIconSize(QtCore.QSize(26, 24))
        self.hide_show.setCheckable(True)
        self.hide_show.setObjectName("hide_show")
        self.horizontalLayout_2.addWidget(self.hide_show)

        self.gen_pass = QtWidgets.QPushButton(self.frame)
        self.gen_pass.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("graphic/gen_pass.png"))
        self.gen_pass.setIcon(icon)
        self.gen_pass.setIconSize(QtCore.QSize(26, 24))
        self.gen_pass.setObjectName("gen_pass")

        self.horizontalLayout_2.addWidget(self.gen_pass)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_3 = QtWidgets.QLabel(self.frame)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.conf_pwd = QtWidgets.QLineEdit(self.frame)
        self.conf_pwd.setEchoMode(QtWidgets.QLineEdit.Password)
        self.conf_pwd.setObjectName("conf_pwd")
        self.horizontalLayout_3.addWidget(self.conf_pwd)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.submit = QtWidgets.QPushButton(self.frame)
        self.submit.setObjectName("submit")
        self.horizontalLayout_4.addWidget(self.submit)
        self.close = QtWidgets.QPushButton(self.frame)
        self.close.setObjectName("close")
        self.horizontalLayout_4.addWidget(self.close)
        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "email"))
        self.label_2.setText(_translate("Form", "password"))
        self.label_3.setText(_translate("Form", "confirm password"))
        self.submit.setText(_translate("Form", "submit"))
        self.close.setText(_translate("Form", "close"))
