# VAGD

Vagrant integration in pwntools

## Installation

 ```bash
 pip install .
 pip install -r requirements.txt
 ```

## Usage

use *template.py* and copy it to *exploit.py* fill out the constants

```bash
# run as process in VM
./exploit.py
# run as gdb server in VM requires tmux
./exploit.py GDB
# run on remote IP:PORT
./exploit.py REMOTE
```

I recommend using [pwndbg](https://github.com/pwndbg/pwndbg).





