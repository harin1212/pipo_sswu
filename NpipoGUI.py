import sys
import time
import math
import numpy as np
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex, pyqtSlot, QWaitCondition
from PyQt5 import uic, QtWidgets, QtCore
from pipopy_v4 import PIPO

form_class = uic.loadUiType("designT.ui")[0]
MKEY=np.array([0x97, 0x22, 0x15, 0x2E, 0xAD, 0x20, 0x1D, 0x7E, 0xD2, 0x28, 0x94, 0x77, 0xDD, 0x16, 0xC4, 0x6D], dtype=np.uint8)

class OptionWindow1(QDialog):
    def __init__(self, parent):
        super(OptionWindow1,self).__init__(parent)

        option_ui = 'designS.ui'
        uic.loadUi(option_ui, self)
        self.buttonBox.accepted.connect(self.download)
        self.buttonBox.rejected.connect(self.hide)
        self.show()

    def download(self):
        OptionWindow.downloadF(self)

class OptionWindow(QDialog):

    def __init__(self, parent, line):
        super(OptionWindow,self).__init__(parent)

        option_ui = 'designC.ui'
        uic.loadUi(option_ui, self)
        self.timer()
        self.contents(line)
        self.cond = QWaitCondition()
        self.pushButton.clicked.connect(self.set_status)
        self.pushButton2.clicked.connect(self.pause_status)
        self.show()

    def set_status(self):
        self.pause = False
        self.cond.wakeAll()

    def pause_status(self):
        self.pause = True

    def timer(self):
        completed = 0.001
        while completed<=100:
            self.progressBar.setProperty("value", completed)
            QtWidgets.QApplication.processEvents()
            self.progressBar.setValue(completed)
            completed += 0.5

        QtWidgets.QApplication.processEvents()
        self.label.setText("변환 완료 !")
        OptionWindow1(self)

    def contents(self, line):
        arrL = list(bin(int(line, 16)))
        if arrL[1] == 'b':
            del arrL[0]
            arrL.remove('b')

        arr = []
        arrL = "".join(arrL)
        for i in range(math.ceil(len(arrL)/8)):
            if i+8 >= len(arrL):
                arr.append(hex(int("{0:b}".format(arrL[i:]).zfill(8),2)))
                break
            arr.append(hex(int(arrL[i:i+8],2)))
            i+=8

        arr = [int(i,16) for i in arr]

        newF = np.array(np.uint8(arr), dtype=np.uint8)
        newF = np.resize(newF, (len(arrL)))
        CIPHER_TEXT = np.zeros(16, dtype=np.uint8)

        K = PIPO(MKEY, 16, 0)
        CIPHER_TEXT = K.ENC(newF)
        global strCipher
        strCipher = K.print_hex(CIPHER_TEXT)

    def downloadF(self):
        MyWindow.download_file(self, strCipher)

class MyWindow(QMainWindow, form_class):

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle("PIPO 변환기 >>")
        self.setWindowIcon(QIcon('ui-sym-ico01.png'))
        self.init_ui()

    def init_ui(self):
        self.btn.clicked.connect(self.open_file)
        self.show()
        
    def convert(self, num, dec):
        i = int(num, dec)
        h = hex(i)
        return h

    def open_file(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self,
                                                         "파일 열기", "",
                                                        "Text File (*.txt);;All File(*.*)",
                                                        options=QtWidgets.QFileDialog.DontResolveSymlinks)
        self.lineEdit.setText(file_name[0])
        f = open(file_name[0],'r')
        line = self.convert(f.readline(), 16)
        OptionWindow(self, line)
        
        f.close()

    def download_file(self, CT):
        file_save = QtWidgets.QFileDialog.getSaveFileName(self, "파일 저장", "*.txt","Text File(*.txt)")
        f = open(file_save[0], 'w')
        f.write(CT)
        f.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.show()
    app.exec_()
