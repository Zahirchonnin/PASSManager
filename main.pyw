from string import ascii_uppercase, ascii_lowercase, digits
from PyQt5 import QtCore, QtWidgets
from cryptor import CryptorManager
import loginGUI, mainGUI, addForm
from hashlib import new, sha256
from pyperclip import copy
from random import choice
from time import sleep
import json
import sip
import os

class Worker(QtCore.QThread):
    def run(self):
        sleep(0.5)


class PASSManager(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        if 'data.json' not in os.listdir('./'):
            with open('data.json', 'w') as f:
                f.write('{}')

        self.Qt = QtCore.Qt
        self.style = """
        QPushButton#addButton{
            background-color: rgba(0, 0, 0, 200);
            color: white;
            border: 2px solid white;
            border-radius: 3px;
            }

        QPushButton#rename::hover, QPushButton#remove::hover, QPushButton#addButton::hover {
            background-color: rgba(255, 255, 255, 200);
            color: black;
        }
        QPushButton#rename, QPushButton#remove {
            background-color: transparent;
            border-radius: 5px;
            max-width: 40px;
            border: 2px solid white;
        }
        """
        self.inintalizeUI()
    
    def inintalizeUI(self):
        self.login_form = QtWidgets.QWidget()
        self.login = loginGUI.Ui_Form()
        self.login.setupUi(self.login_form)

        self.login.submit.clicked.connect(self.checkData)
        self.login.submit_regi.clicked.connect(self.register)
        self.login.close_bt.clicked.connect(lambda: self.close(False))
        self.login.minimize_bt.clicked.connect(
            lambda: self.login_form.showMinimized()
        )

        self.login.show_hide.clicked.connect(self.showPassword)
        self.login.show_hide_2.clicked.connect(self.showPassword)

        self.main = mainGUI.Ui_Form()
        self.main.setupUi()
        self.main.setStyleSheet(self.style)

        self.main.close_bt.clicked.connect(lambda: self.close(True))
        self.main.minimize_bt.clicked.connect(
            lambda: self.main.showMinimized()
        )

        self.main.add_account.clicked.connect(self.addAcount)
        self.main.accounts.itemDoubleClicked.connect(self._Copy)
        self.main.add_email.clicked.connect(self.getAddForm)
        self.main.rename.clicked.connect(self.renameItem)
        self.main.remove.clicked.connect(self.removeItem)
        self.main.gen_pass.clicked.connect(self.genPass)
        

        self.add_form = QtWidgets.QWidget()
        self.add = addForm.Ui_Form()
        self.add.setupUi(self.add_form)

        self.add.hide_show.clicked.connect(self.showPassword)
        self.add.close.clicked.connect(self.back)

        self.add.gen_pass.clicked.connect(
            lambda: self.genPass(new=True)
            )

        self.add.submit.clicked.connect(self.SingData)

        self.message = QtWidgets.QMessageBox(self)

        self.login_form.show()
    
    def checkData(self):
        username = self.login.username.text()
        self.login.username.clear()
        with open('data.json') as f:
            try:
                data = json.loads(f.read())
                data = self.load(data)
            except json.decoder.JSONDecodeError:
                return self.message.information(self, 'Not found',
                'There is no account, you should register first',
                self.message.Ok, self.message.Ok)
        
        pwd = self.login.password.text()
        self.login.password.clear()
        
        if not pwd or not username:
            self.message.information(self, 'empty fields',
            'You should fill all fields', self.message.Ok, self.message.Ok)
            return

        try:
            userDATA = data[username]
            key = (pwd.encode() + userDATA['salt'])[:32]

            if sha256(key).hexdigest() != userDATA['key']:

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
                self.encryptManager = CryptorManager(key)
                self.accounts = userDATA['Accounts']
                self.accounts = self.encryptManager.decryptor(self.accounts)
                self.username = username
                self.loadData(self.accounts)
                self.login_form.hide()
                self.main.show()
        except KeyError:
            self.message.information(
                self, 'Not found', 
                f' This username "{username}" not singed in.',
                self.message.Ok, self.message.Ok
                )

    def register(self):
        with open('data.json') as f:
            try:
                data = self.load(json.loads(f.read()))
            except json.decoder.JSONDecodeError:
                data = {}

        username = self.login.username_regi.text()
        pwd = self.login.password_regi.text()
        conf_pwd = self.login.pwd_conf_regi.text()

        self.login.username_regi.clear()
        self.login.password_regi.clear()
        self.login.pwd_conf_regi.clear()

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
            self.encryptManager = CryptorManager(key)
            self.accounts = data[username]['Accounts']
            self.username = username
            self.login_form.hide()
            self.main.show()



    def showPassword(self, state):

        if state:

            self.login.password.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.login.password_regi.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.add.password.setEchoMode(QtWidgets.QLineEdit.Normal)
        
        else:
            self.login.password.setEchoMode(QtWidgets.QLineEdit.Password)
            self.login.password_regi.setEchoMode(QtWidgets.QLineEdit.Password)
            self.add.password.setEchoMode(QtWidgets.QLineEdit.Password)
    
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
            self.accounts[account_name] = {}
            item = QtWidgets.QTreeWidgetItem(self.main.accounts)
            item.setText(0, account_name)
            item.setData(0, 100, account_name)
            self.main.accounts.addTopLevelItem(item)

    
    def getAddForm(self):
        try:
            item = self.main.accounts.currentItem()
            if item.data(0, 100):
                account_name = item.text(0)
                self.add.title.setText(f"Add new account to {account_name}")
                self.main.setDisabled(True)
                self.add_form.show()    
            
            else:
                self.message.information(self, 'denied',
                'You can\'t add account here.', self.message.Ok, self.message.Ok)
        
        except AttributeError:
            self.message.information(self, 'Selected!', 
            'You should select item first.', self.message.Ok, self.message.Ok)

    def SingData(self):
        email = self.add.email.text()
        pwd = self.add.password.text()
        conf_pwd = self.add.conf_pwd.text()
        if not email or not pwd:
            return self.message.information(self, 'Empty filled!',
            'You should fill all fields', self.message.Ok,
            self.message.Ok)
        
        if pwd != conf_pwd:
            return self.message.information(self, 'Unmatched!',
            'Unmatched password, Try again!', self.message.Ok,
            self.message.Ok)
        
        
        parent = self.main.accounts.currentItem()
        em_item = QtWidgets.QTreeWidgetItem()
        em_item.setText(0, email)
        em_item.setData(0, 11, email)

        pwd_item = QtWidgets.QTreeWidgetItem()
        pwd_item.setText(0, pwd)
        pwd_item.setData(0, 3, pwd)

        em_item.addChild(pwd_item)
        parent.addChild(em_item)
        self.accounts[parent.text(0)][email] = pwd

        self.back()
    
    def back(self):
        self.add_form.close()
        self.main.setEnabled(True)

    def genPass(self, new=False):

        gen = x = lambda _type, _len: ''.join([choice(_type) for i in range(_len)])
        password = gen(ascii_uppercase, 3) + gen(ascii_lowercase, 4) + gen(digits, 4)
        if new:
            self.add.password.setText(password)
            self.add.conf_pwd.setText(password)
        
        else:
            try:
                item = self.main.accounts.currentItem()
                if item.data(0, 3):
                    resp = self.message.question(self, 'Generate password',
                    "You will lose your current password, are you sure?",
                    self.message.Yes | self.message.No, self.message.No)
                
                    if resp == self.message.Yes:
                        item.setText(0, password)
                        item.setData(0, 3, password)

                        email = item.parent()
                        account = email.parent().text(0)
                        self.accounts[account][email.text(0)] = password
                else:
                    self.message.information(self, 'denied',
                    'This is not password field.', self.message.Ok, self.message.Ok)
            except AttributeError:
               self.message.information(self, 'Selected!', 
               'You should select item first.', self.message.Ok, self.message.Ok)
    
    def renameItem(self):
        try:
            item = self.main.accounts.currentItem()
            if item.data(0, 100):
                msg = 'account'; i = 100

            elif item.data(0, 11):
                msg = 'email'; i = 11
                account = item.parent().text(0)

            else:
                msg = 'password'; i = 3
                email = item.parent()
                account = email.parent().text(0)
                email = email.text(0)

            new_name, ok = QtWidgets.QInputDialog.getText(self, 'Edit', f'Enter new {msg}')
            if ok:
                if msg == 'account':
                    self.accounts[new_name] = self.accounts.pop(item.text(0))
                
                elif msg == 'email':
                    self.accounts[account][new_name] = self.accounts[account].pop(item.text(0))
                
                else:
                    self.accounts[account][email] = new_name

                item.setData(0, i, new_name)
                item.setText(0, new_name)
        
        except AttributeError:
            self.message.information(self, 'Selected!', 
            'You should select item first.', self.message.Ok, self.message.Ok)
            
    def removeItem(self):
        try:
            item = self.main.accounts.currentItem()
            if item.data(0, 100):
                msg = 'account'; i = 100

            elif item.data(0, 11):
                msg = 'email'; i = 11
                account = item.parent().text(0)
            else:
                return self.message.information(self, 'denied',
                'You can\'t remove only a password.', self.message.Ok, self.message.Ok)

            resp = self.message.question(self, 'Remove', 
            f'Are you sure you want to remove this {msg}?',
            self.message.Yes | self.message.No, self.message.No)
            if resp == self.message.Yes:
                if msg == 'account':
                    del self.accounts[item.text(0)]
                
                else:
                    del self.accounts[account][item.text(0)]
                
                sip.delete(item)

        except TypeError:
            self.message.information(self, 'Selected!', 
            'You should select item first.', self.message.Ok, self.message.Ok)
            
        
    def _Copy(self):
        item = self.main.accounts.currentItem().text(0)
        copy(item)
        self.main.copy_label.show()
        self.worker = Worker()
        self.worker.start()
        self.worker.finished.connect(
            lambda: self.main.copy_label.hide()
            )

    def close(self, save):
        answer = self.message.warning(self, 'Quit?', 
        'Are you sure you want to exit?', self.message.Yes | self.message.No,
        self.message.No)

        if answer == self.message.Yes:
            if save:
                with open('data.json') as f:
                    data = json.loads(f.read())
                    data = self.load(data)
                    
                data[self.username]['Accounts'] = self.encryptManager.encryptor(self.accounts)
                self.save(data, True)
                self.main.accounts.clear()
                self.main.hide()
                self.login_form.show()
            else:
                exit()
    
    def loadData(self, data):
        for account, account_info in data.items():
            ac_item = QtWidgets.QTreeWidgetItem(self.main.accounts)
            ac_item.setText(0, account)
            ac_item.setData(0, 100, account)
            self.main.accounts.addTopLevelItem(ac_item)
            for email, pwd in account_info.items():
                em_item = QtWidgets.QTreeWidgetItem()
                em_item.setText(0, email)
                em_item.setData(0, 11, email)

                pwd_item = QtWidgets.QTreeWidgetItem()
                pwd_item.setText(0, pwd)
                pwd_item.setData(0, 3, pwd)

                em_item.addChild(pwd_item)
                ac_item.addChild(em_item)


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = PASSManager()
    sys.exit(app.exec_())