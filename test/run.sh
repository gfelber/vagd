#!/bin/sh
if [[ -z "$VIRTUAL_ENV" ]]; then
    source ../venv/bin/activate
fi

VAGRANT_CWD=.vagd vagrant halt;
kill $(pgrep qemu);
echo STARTING TEST;
python test.py GDB;
