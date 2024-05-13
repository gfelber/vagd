#!/bin/sh
pip install -U ../ python-vagrant docker;
VAGRANT_CWD=.vagd vagrant halt;
kill $(pgrep qemu);
echo STARTING TEST;
python test.py GDB;
