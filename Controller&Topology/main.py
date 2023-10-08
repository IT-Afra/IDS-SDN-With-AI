#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess

import sys


from ryu.cmd import manager



def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')
    sys.argv.append('ids.py')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    os.system('gnome-terminal --window-with-profile=MY_PROFILE -e "python3 ./topo.py"')
    main()