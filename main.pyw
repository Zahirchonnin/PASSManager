from PyQt5 import QtCore, QtGui, QtWidgets
import loginGUI, mainGUI, addForm
from hashlib import sha256
import os
import json


class PASSManager(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.style = """
    QPushButton#addButton{
        background-color: rgba(0, 0, 0, 200);
        color: white;
        border: 2px solid white;
        border-radius: 3px;
        margin-left: 500px
    }
    QPushButton#addButton::hover{
        background-color: rgba(255, 255, 255, 200);
        color: black;
    }
    """
        self.inintalizeUI()
    
    def inintalizeUI(self):
        self.login_form = QtWidgets.QWidget()
        self.login = loginGUI.Ui_Form()
        self.login.setupUi(self.login_form)

        self.login.submit.clicked.connect(self.checkData)
        self.login.submit_regi.clicked.connect(self.register)
        self.login.close_bt.clicked.connect(
            lambda: self.close(self.login_form)
        )
        self.login.minimize_bt.clicked.connect(
            lambda: self.login_form.showMinimized()
        )

        self.login.show_hide.clicked.connect(self.showPassword)
        self.login.show_hide_2.clicked.connect(self.showPassword)

        self.main_form = QtWidgets.QWidget()
        self.main_form.setStyleSheet(self.style)
        self.main = mainGUI.Ui_Form()
        self.main.setupUi(self.main_form)

        self.main.close_bt.clicked.connect(
            lambda: self.close(self.main_form)
        )
        self.main.minimize_bt.clicked.connect(
            lambda: self.main_form.showMinimized()
        )

        self.main.add_account.clicked.connect(self.addAcount)

        self.add_form = QtWidgets.QWidget()
        self.add = addForm.Ui_Form()
        self.add.setupUi(self.add_form)

        self.add.hide_show.clicked.connect(self.showPassword)
        self.add.close.clicked.connect(
            lambda: self.add_form.hide()
        )
        self.add.submit.clicked.connect(self.SingData)

        self.message = QtWidgets.QMessageBox(self)

        self.login_form.show()
    
    def checkData(self):
        username = self.login.username.text()
        with open('data.json') as f:
            data = json.loads(f.read())
            data = self.load(data)
        
        pwd = self.login.password.text()
        
        if not pwd or not username:
            self.message.information(self, 'empty fileds',
            'You should fill all fileds', self.message.Ok, self.message.Ok)
            return

        try:
            self.userDATA = data[username]
            key = (pwd.encode() + self.userDATA['salt'])[:32]
            if sha256(key).hexdigest() != self.userDATA['key']:

                self.message.information(
                    self, 'Wrong passowrd!', 
                    "The password that you've entered is incorrect", 
                    self.message.Ok, self.message.Ok
                    )

            else:
                self.message.information(
                    self, 'Wellcome', 
                    "Wellcom to your room %s" % username,
                    self.message.Ok, self.message.Ok
                    )
                self.login_form.hide()
                self.main_form.show()
        except KeyError:
            self.message.information(
                self, 'Not found', 
                f' This username "{username}" not singed in.',
                self.message.Ok, self.message.Ok
                )

    def register(self):
        with open('data.json') as f:
            data = self.load(json.loads(f.read()))
        
        username = self.login.username_regi.text()
        pwd = self.login.password_regi.text()
        conf_pwd = self.login.pwd_conf_regi.text()

        if username in data:
            self.message.information(self, 'Username used',
            f'This username "{username}" already used.',
            self.message.Ok, self.message.Ok)
        
        elif pwd != conf_pwd:
            self.message.information(self, 'Wrong password!',
            'Unmatched passwords', self.message.Ok, self.message.Ok)
        
        elif len(pwd) < 8 or (pwd.isalpha() and pwd.isnumeric()):
            self.message.information(
                self, 'Weak password', 'You entred a weak password',
                self.message.Ok, self.message.Ok 
            )
        
        else:
            salt = os.urandom(32)
            key = (pwd.encode() + salt)[:32]
            hashed_key = sha256(key).hexdigest()
            data[username] = {'salt': salt, 'key': hashed_key, 'Accounts': {}}
            self.save(data, save=True)
            self.message.information(
                self, 'Wellcome', 
                'successfully singed up, Wellcome',
                self.message.Ok, self.message.Ok
                )
            self.login_form.hide()
            self.main_form.show()



    def showPassword(self, state):

        if state:

            self.login.password.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.login.password_regi.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.add.password.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.add.conf_pwd.setEchoMode(QtWidgets.QLineEdit.Normal)
        
        else:
            self.login.password.setEchoMode(QtWidgets.QLineEdit.Password)
            self.login.password_regi.setEchoMode(QtWidgets.QLineEdit.Password)
            self.add.password.setEchoMode(QtWidgets.QLineEdit.Password)
            self.add.conf_pwd.setEchoMode(QtWidgets.QLineEdit.Password)
    
    def load(self, data):
        for k, v in data.items():
            if isinstance(v, list):
                data[k] = bytes(v)
            
            elif isinstance(v, dict):
                data[k] = self.load(data=v)
        
        return data
    
    def save(self, data, save):
        for k, v in data.items():
            if isinstance(v, bytes):
                data[k] = list(v)
            
            elif isinstance(v, dict):
                data[k] = self.save(v, False)
        
        if save:
            with open('data.json', 'w') as f:
                f.write(json.dumps(data))
            
        else:
            return data
        
    def addAcount(self):
        account_name, ok = QtWidgets.QInputDialog.getText(self, 'account name', 'Enter account name')
        if ok:
            index = self.main.accounts.topLevelItemCount()

            item = QtWidgets.QTreeWidgetItem()
            item.setText(0, account_name)
            add_email = QtWidgets.QPushButton(text='add email')
            add_email.setObjectName('addButton')
            add_email.clicked.connect(lambda: self.add_form.show())

            self.main.accounts.addTopLevelItem(item)
            self.main.accounts.setItemWidget(item, 0, add_email)
    
    def SingData(self):
        email = self.add.email.text()
        pwd = self.add.password.text()
        conf_pwd = self.add.conf_pwd.text()
        if pwd != conf_pwd:
            return self.message.information(self, 'Unmatched!',
            'Unmatched password, Try again!', self.message.Ok,
            self.message.Ok)
        
        item = QtWidgets.QTreeWidgetItem()
        item.setText(0, email)
        childitem = QtWidgets.QTreeWidgetItem()
        #TODO
        """
        add password generater in addForm.py
        add show/hide password in email child
        
        """
        childitem.addWidget()
        item.addChild()
        self.main.accounts.currentItem().addChild(item)



    def close(self, form):
        answer = self.message.warning(self, 'Quit?', 
        'Are you sure you want to exit?', self.message.Yes | self.message.No,
        self.message.No)

        if answer == self.message.Yes:
            form.close()

if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = PASSManager()
    sys.exit(app.exec_())