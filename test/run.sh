#!/bin/sh
source venv/bin/activate
pip install ../.
python test.py GDB
