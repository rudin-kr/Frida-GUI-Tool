# -*- coding: utf-8 -*-
import ctypes
import sys

from PyQt5.QtWidgets import *

from ui.toolbarcontrol import ToolBarControl
from os import environ  # environ 를 import 해야 아래 suppress_qt_warnings 가 정상 동작하니다


def suppress_qt_warnings():  # 해상도별 글자크기 강제 고정하는 함수
    environ["QT_DEVICE_PIXEL_RATIO"] = "0"
    environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    environ["QT_SCREEN_SCALE_FACTORS"] = "1"
    environ["QT_SCALE_FACTOR"] = "1"


if __name__ == '__main__':
    if ctypes.windll.shell32.IsUserAnAdmin():
        print('This Tool is executed as administrator.')
    else:
        print('This Tool is executed as User.')
        print('If your target is Windows Application, this Tool need to run as administrator.')
        print('If your target is Mobile App, this Tool doesn\'t care of it.')

    suppress_qt_warnings()

    app = QApplication(sys.argv)

    toolbar_control = ToolBarControl()
    toolbar_control.show()

    sys.exit(app.exec_())
