import os
# set PWNLIB_NOTERM to prevent sys.stdin overwrite
os.environ['PWNLIB_NOTERM'] = '1'

from vagd.box import Box
from vagd.virts import *



