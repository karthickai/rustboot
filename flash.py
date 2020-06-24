from cfonts import render, say
import time
import struct
import socket
import argparse
import crcmod

try:
    from tqdm import tqdm
except ImportError:
    print("Notice: tqdm not installed, install for progress bars.")

    def tqdm(x, *args, **kwargs):
        return x


commands = {
    "erase": 2,
    "write": 3,
    "boot": 4,
}


errors = {
    0: "Success",
    1: "Invalid Address",
    2: "Length Not Multiple of 4",
    3: "Length Too Long",
    4: "Data Length Incorrect",
    5: "Erase Error",
    6: "Write Error",
    7: "Flash Error",
    8: "Network Error",
    9: "Internal Error",
}


class BootloaderError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        if self.errno in errors:
            return "{}".format(errors[self.errno])
        else:
            return "Unknown error {}".format(self.errno)


class MismatchError(Exception):
    def __init__(self, addr, tx, rx):
        self.addr = addr
        self.tx = tx
        self.rx = rx

    def __str__(self):
        return "Mismatch at address {:08X}: {:02X}!={:02X}".format(
            self.addr, self.tx, self.rx)


def interact(hostname, port, command, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((hostname, port))
    s.sendall(command)
    data = check_response(s.recv(2048))
    s.close()
    time.sleep(0.01)
    return data


def check_response(data):
    errno = struct.unpack("<I", data[:4])[0]
    if errno != 0:
        raise BootloaderError(errno)
    return data[4:]


def erase_cmd(hostname, port, address, length):
    cmd = struct.pack("<III", commands['erase'], address, length)
    interact(hostname, port, cmd, timeout=20.0)


def write_cmd(hostname, port, address, data):
    cmd = struct.pack("<III{}B".format(len(data)), commands['write'],
                      address, len(data), *data)
    interact(hostname, port, cmd)


def boot_cmd(hostname, port):
    cmd = struct.pack("<I", commands['boot'])
    interact(hostname, port, cmd)


def write_file(hostname, port, chunk_size, address, data):
    # We need to write in multiples of 4 bytes (since writes are word-by-word),
    # so add padding to the end of the data.
    length = len(data)
    if length % 4 != 0:
        padding = 4 - length % 4
        data += b"\xFF"*padding
        length += padding
    segments = length // chunk_size
    if length % chunk_size != 0:
        segments += 1

    print("Erasing (may take a few seconds)...")
    erase_cmd(hostname, port, address, length)

    print("Writing {:.02f}kB in {} segments...".format(length/1024, segments))
    for sidx in tqdm(range(segments), unit='kB', unit_scale=chunk_size/1024):
        saddr = address + sidx*chunk_size
        sdata = data[sidx*chunk_size:(sidx+1)*chunk_size]
        time.sleep(0.250)
        write_cmd(hostname, port, saddr, sdata)

    print("Writing completed successfully. Reading back...")
    boot_cmd(hostname, port)


def run():
    try:
        output = render('RUST', colors=['red', 'yellow'],
                        align='center', line_height=0)
        print(output)

        say("Bootloader", align='center',
            colors=['red', 'cyan', 'green'], font='chrome', line_height=0)

        say("Configure Cortex-M Series Microcontroller", align='left',
            colors=['yellow'], font='console', line_height=0)
        host = input("Enter IP Address : ")
        port = input("Enter Port Address: ")
        filebin = input("Enter Application bin file path: ")
        display_text_init = "Connecting to Microcontroller " + host + ":" + port
        print(display_text_init, end=" ")

        for _ in range(4):
            print(".", end="")
            time.sleep(1)
        print("")
        print("Connected")
        print("Flashing Started .................")
        bindata = open(filebin, "rb").read()
        write_file(host, int(port), 256, 0x08080000,
                   bindata)

    except OSError as e:
        print("Operation done.")
    except BootloaderError as e:
        print("Bootloader error:", e)
    except MismatchError as e:
        print("Mismatch error:", e)


if __name__ == "__main__":
    run()
