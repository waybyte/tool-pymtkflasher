############################################################################
#
# Copyright (c) 2021 WAYBYTE Solutions
#
# MT6261/MT2503 Flasher in Python
#
# Based on MT6261 Flash Utility By Georgi Angelov
#
############################################################################
#
# Copyright (C) 2019 Georgi Angelov. All rights reserved.
# Author: Georgi Angelov <the.wizarda@gmail.com> WizIO
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name WizIO nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
############################################################################
# Dependency:
#      https://github.com/pyserial/pyserial/tree/master/serial
############################################################################

import os
import sys
import struct
import time
import os.path
from os.path import join
from serial import Serial
import serial.serialutil as serialutil
from binascii import hexlify
import inspect
import argparse
from argparse import RawTextHelpFormatter

APP_VER="0.2.0"

DEBUG = False

NONE = ''
CONF = b'\x69'
STOP = b'\x96'
ACK = b'\x5A'
NACK = b'\xA5'

CMD_READ_16 = b'\xA2'
CMD_READ16 = b'\xD0'
CMD_READ32 = b'\xD1'
CMD_WRITE16 = b'\xD2'
CMD_WRITE32 = b'\xD4'
CMD_JUMP_DA = b'\xD5'
CMD_SEND_DA = b'\xD7'
CMD_SEND_EPP = b'\xD9'

DA_SYNC = b'\xC0'
DA_FORMAT_FAT = b'\xB8'
DA_CONFIG_EMI = b'\xD0'
DA_POST_PROCESS = b'\xD1'
DA_SPEED = b'\xD2'
DA_MEM = b'\xD3'
DA_FORMAT = b'\xD4'
DA_WRITE = b'\xD5'
DA_READ = b'\xD6'
DA_WRITE_REG16 = b'\xD7'
DA_READ_REG16 = b'\xD8'
DA_FINISH = b'\xD9'
DA_GET_DSP_VER = b'\xDA'
DA_ENABLE_WATCHDOG = b'\xDB'
DA_NFB_WRITE_BLOADER = b'\xDC'
DA_NAND_IMAGE_LIST = b'\xDD'
DA_NFB_WRITE_IMAGE = b'\xDE'
DA_NAND_READPAGE = b'\xDF'

DA_CLEAR_POWERKEY_IN_META_MODE_CMD = b'\xB9'
DA_ENABLE_WATCHDOG_CMD = b'\xDB'
DA_GET_PROJECT_ID_CMD = b'\xEF'

UART_BAUD_921600 = b'\x01'
UART_BAUD_460800 = b'\x02'
UART_BAUD_230400 = b'\x03'
UART_BAUD_115200 = b'\x04'

if sys.version_info >= (3, 0):
    def xrange(*args, **kwargs):
        return iter(range(*args, **kwargs))


def ERROR(message):
    print("\nERROR: {}\n".format(message))
    exit(2)


def ASSERT(flag, message):
    if flag == False:
        ERROR(message)

class progressbar:
    def __init__(self, prefix="", total=100, size=50, f=sys.stdout):
        self.reset(prefix, total, size, f)

    def reset(self, prefix="", total=100, size=50, f=sys.stdout):
        self.prefix = prefix
        self.total = total
        self.count = 0
        self.size = size
        self.file = f
        self.isatty = f.isatty()
        self.hash = -1;

    def update(self, j):
        self.count += j
        x = int(self.size * self.count / self.total)
        per = int(self.count * 100 / self.total)
        if self.isatty:
            self.file.write("%s [%s%s] %i%%\r" %
                    (self.prefix, "#"*x, "."*(self.size-x), per))
        elif self.hash != x:
            if self.hash == -1:
                self.hash = x
                self.file.write("%s\n|%s" % (self.prefix, "#"*x))
            else:
                self.file.write("%s" % ("#"*(x-self.hash)))
                self.hash = x
        self.file.flush()
    
    def end(self):
        if not self.isatty:
            self.file.write("| 100%\n")
        else:
            self.file.write("\n")
        self.file.flush()


def hexs(s):
    return hexlify(s).decode("ascii").upper()


class MT6261:
    DA = {
        "MT6261": {
            "1": {"offset": 0x00000, "size": 0x00718, "address": 0x70007000},
            "2": {"offset": 0x00718, "size": 0x1e5c8, "address": 0x10020000}
        }
    }

    def __init__(self):
        self.dir = os.path.dirname(os.path.realpath(__file__))

    def open(self):
        try:
            self.s = Serial(self.port, 115200)
        except serialutil.SerialException as ex:
            ERROR(ex)

    def crc_word(self, data, chs=0):
        for i in xrange(0, len(data), 1):
            if (sys.version_info[0] < 3):
                chs += ord(data[i]) & 0xFF
            else:
                chs += data[i] & 0xFF
        return chs & 0xFFFF

    def send(self, data, sz=0):
        r = ""
        if len(data):
            if DEBUG:
                print("--> {}".format(hexs(data)))
            self.s.write(data)
        if sz > 0:
            r = self.s.read(sz)
            if DEBUG:
                print("<-- {}".format(hexs(r)))
        return r

    def cmd(self, cmd, sz=0):
        r = ""
        size = len(cmd)
        if size > 0:
            r = self.send(cmd, size)
            ASSERT(r == cmd, "Command response fail: {} != {}".format(hexs(cmd), hexs(r)))
        if sz > 0:
            r = self.s.read(sz)
            if DEBUG:
                print("<-- {}".format(hexs(r)))
        return r

    def da_read_16(self, addr, sz=1):
        r = self.cmd(CMD_READ_16 + struct.pack(">II", addr, sz), sz*2)
        return struct.unpack(">" + sz * 'H', r)

    def da_read16(self, addr, sz=1):
        r = self.cmd(CMD_READ16 + struct.pack(">II", addr, sz), (sz*2)+4)
        return struct.unpack(">" + sz * 'HHH', r)

    def da_write16(self, addr, val):
        r = self.cmd(CMD_WRITE16 + struct.pack(">II", addr, 1), 2)
        ASSERT(r == b"\0\1", "WR16 CMD {} != {}".format(hexs(r),hexs(b"\0\1")))
        r = self.cmd(struct.pack(">H", val), 2)
        ASSERT(r == b"\0\1", "WR16 VAL {} != {}".format(hexs(r),hexs(b"\0\1")))

    def da_write32(self, addr, val):
        r = self.cmd(CMD_WRITE32 + struct.pack(">II", addr, 1), 2)
        ASSERT(r == b"\0\1", "WR32 CMD {} != {}".format(hexs(r),hexs(b"\0\1")))
        r = self.cmd(struct.pack(">I", val), 2)
        ASSERT(r == b"\0\1", "WR32 VAL {} != {}".format(hexs(r),hexs(b"\0\1")))

    def da_read32(self, addr, sz=1):
        r = self.cmd(CMD_READ32 + struct.pack(">II", addr, sz), (sz*4)+4)
        return struct.unpack(">H" + (sz*'I')+"H", r)

    def da_send_da(self, address, size, data, block=4096):
        r = self.cmd(CMD_SEND_DA + struct.pack(">III",
                                               address, size, block), 2)
        ASSERT(r == b"\0\0", "SEND DA CMD {} != {}".format(hexs(r),hexs(b"\0\0")))
        while data:
            self.s.write(data[:block])
            data = data[block:]
            self.pb.update(block)
        r = self.cmd(b"", 4)  # checksum

    def sendFlashInfo(self, offset):
        for i in range(512):
            data = self.get_da(offset, 36)
            ASSERT(data[:4] != b'\xFF\xFF\0\0', "Invalid flash info: {}".format(hexs(data[:4])))
            offset += 36
            r = self.send(data, 1)
            if r == ACK:
                r = self.cmd(b"", 2)
                ASSERT(r == b'\xA5\x69', "Flashinfo END: {}".format(hexs(r)))
                break
            ASSERT(r == CONF, "Flashinfo ACK Fail: {}".format(hexs(r)))

    def get_da(self, offset, size):
        self.fd.seek(offset)
        data = self.fd.read(size)
        return data

    def loadBootLoader(self, fname=""):
        fname = join(self.dir, fname)
        ASSERT(os.path.isfile(fname) == True, "Missing download agent: " + fname)
        self.fd = open(fname, "rb")

    def connect(self, timeout=30):
        self.s.timeout = 0.02
        start = time.time()
        print("Please reset the device.\nWaiting......")
        sys.stdout.flush()
        c = 0
        while True:
            c += 1
            self.s.write(b"\xA0")
            if self.s.read(1) == b"\x5F":
                self.s.write(b"\x0A\x50\x05")
                r = self.s.read(3)
                if r == b"\xF5\xAF\xFA":
                    break
                else:
                    ERROR("BOOT")
            if ((time.time() - start) > timeout):
                ERROR("Timeout")

        self.s.timeout = 1.0
        BB_CPU_HW = self.da_read_16(0x80000000)[0]  # BB_CPU_HW = CB01
        BB_CPU_SW = self.da_read_16(0x80000004)[0]  # BB_CPU_SW = 0001
        BB_CPU_ID = self.da_read_16(0x80000008)[0]  # BB_CPU_ID = 6261
        BB_CPU_SB = self.da_read_16(0x8000000C)[0]  # BB_CPU_SB = 8000
        self.da_write16(0xa0700a28, 0x4010)  # 01
        self.da_write16(0xa0700a00, 0xF210)  # 02
        self.da_write16(0xa0030000, 0x2200)  # 03
        self.da_write16(0xa071004c, 0x1a57)  # 04
        self.da_write16(0xa071004c, 0x2b68)  # 05
        self.da_write16(0xa071004c, 0x042e)  # 06
        self.da_write16(0xa0710068, 0x586a)  # 07
        self.da_write16(0xa0710074, 0x0001)  # 08
        self.da_write16(0xa0710068, 0x9136)  # 09
        self.da_write16(0xa0710074, 0x0001)  # 10
        self.da_write16(0xa0710000, 0x430e)  # 11
        self.da_write16(0xa0710074, 0x0001)  # 12
        self.da_write32(0xa0510000, 0x00000002)  # ???
        if BB_CPU_ID == 0x6261:
            self.chip = "MT6261"
            self.loadBootLoader("mt6261_da.bin")
        else:
            ERROR("Flasher does not support this SoC: %04x" % BB_CPU_ID)

    def da_start(self):
        self.pb = progressbar(
            "Download DA", self.DA[self.chip]["1"]["size"] + self.DA[self.chip]["2"]["size"])
        self.pb.update(0)
        # SEND_DA_1
        offset = self.DA[self.chip]["1"]["offset"]
        size = self.DA[self.chip]["1"]["size"]
        addr1 = self.DA[self.chip]["1"]["address"]
        data = self.get_da(offset, size)
        self.da_send_da(addr1, size, data, 0x400)  # <--chs = D5AF.0000
        # SEND_DA_2
        offset = self.DA[self.chip]["2"]["offset"]
        size = self.DA[self.chip]["2"]["size"]
        addr2 = self.DA[self.chip]["2"]["address"]
        data = self.get_da(offset, size)
        self.da_send_da(addr2, size, data, 0x800)  # <--chs = E423.0000
        offset += size
        # CMD_JUMP_DA
        r = self.cmd(CMD_JUMP_DA + struct.pack(">I", addr1), 2)  # D5-
        ASSERT(r == b"\0\0", "DA JUMP Fail: {}".format(hexs(r)))
        # <-- C003028E DA_INFO: 0xC0 , Ver : 3.2 , BBID : 0x8E
        r = self.cmd(b"", 4)
        self.send(
            b"\xa5\x05\xfe\x00\x08\x00\x70\x07\xff\xff\x02\x00\x00\x01\x08", 1)  # ??
        # FLASH ID INFOS
        self.sendFlashInfo(offset)
        self.send(b"\0\0\0\0", 256)  # EMI_SETTINGS ??
        self.pb.end()
    
    def da_changebaud(self, baud=460800):
        if baud == 115200:
            return

        speed_table = {
            921600: UART_BAUD_921600,
            460800: UART_BAUD_460800,
            230400: UART_BAUD_230400,
            115200: UART_BAUD_115200
        }
        r = self.send(DA_SPEED + speed_table.get(baud,
                                                 UART_BAUD_460800) + b"\x01", 1)
        ASSERT(r == ACK, "DA Change Baud CMD ACK Fail: {}".format(hexs(r)))
        self.send(ACK)
        self.s.baudrate = baud
        time.sleep(0.2)
        for i in range(10):
            r = self.send(DA_SYNC, 1)
            if (r == DA_SYNC):
                break
            time.sleep(0.02)
        ASSERT(r == DA_SYNC, "DA SPEED sync fail")
        ASSERT(self.send(ACK, 1) == ACK, "DA SPEED ACK fail")
        for i in range(256):
            loop_val = struct.pack(">B", i)
            ASSERT(self.send(loop_val, 1) == loop_val, "DA SPEED Loop fail")

    # NACK: disable FOTA feature
    def da_mem(self, address, size, ftype, file_count=1, fota=NACK):
        self.send(DA_MEM + fota + struct.pack(">B", file_count))

        for i in range(file_count):
            start_addr = address[i] & 0x07FFFFFF
            end_addr = start_addr + size[i] - 1
            r = self.send(struct.pack(">III", start_addr, end_addr, ftype[i]), 1)
            ASSERT(r == ACK, "DA_MEM ACK")

        r = struct.unpack(">BB", self.send(NONE, 2)) #filecount + ACK
        #ASSERT(r[0] == file_count, "File count does not match")

        for i in range(file_count):
            format_acks = struct.unpack(">I", self.send(NONE, 4))[0] # Format Ack Count for each file
            self.pb.reset("Pre-Format " + str(i), format_acks + 1) # Format progress bar
            self.pb.update(0)
            for i in range(format_acks):
                ASSERT(self.send(NONE, 1) == ACK, "Firmware memory format failed")
                self.pb.update(1)
            self.pb.update(1)
            self.pb.end()

        ASSERT(self.send(NONE, 1) == ACK, "Firmware memory format failed 2")

    def da_write(self, block=4096):
        ASSERT(self.send(DA_WRITE, 1) == ACK, "DA_WRITE ACK")
        # Sequential Erase (0x1). (0x0) for Best-Effort Erase, packet_length
        r = self.send(struct.pack(">BI", 0, block), 2)
        ASSERT(r == ACK + ACK, "DA_WRITE OK")

    def da_write_data(self, fw_data, block=4096):
        count = 0
        i = 0
        c = []
        for data in fw_data:
            w = 0
            c.append(0)
            while data:
                self.s.write(ACK)
                self.s.write(data[:block])
                w = self.crc_word(data[:block])
                r = self.send(struct.pack(">H", w), 1)
                if r == CONF:
                    self.pb.update(len(data[:block]))
                    c[i] += w
                    data = data[block:]
                elif r == NACK:
                    # need to wait for ack before sending next packet
                    start_time = time.time()
                    while True:
                        r = self.send(NONE, 1)
                        if r == ACK:
                            self.s.write(CONF)
                            break
                        ASSERT((time.time() - start_time) < 60, "Firmware Data write timeout")
                else:
                    ASSERT(False, "Firmware fail")

            i += 1
            count += 1

        ack_count = 0
        start_time = time.time()
        while True:
            r = self.send(NONE, 1)
            if r == ACK:
                ack_count += 1
                if ack_count == 3:
                    break
            ASSERT((time.time() - start_time) < 10, "Firmware Write Error")

        for i in range(count):
            r = self.send(struct.pack(">H", c[i] & 0xFFFF), 1)
            ASSERT(r == ACK, "Firmware write ack failed")
        # <-- 14175A  is error

    def printVersion(self):
        self.send(DA_GET_PROJECT_ID_CMD, 1)
        r = self.send(DA_GET_PROJECT_ID_CMD, 256)
        r = r[:24].rstrip(b"\0")
        r = r.lstrip(b"\0")
        print("Version", r[:24].rstrip(b"\0"))

    def da_reset(self):
        r = self.send(DA_CLEAR_POWERKEY_IN_META_MODE_CMD, 1)  # <-- 5A
        r = self.send(b'\xC9\x00', 1)  # ???<-- 5A
        r = self.send(DA_ENABLE_WATCHDOG_CMD +
                      b'\x01\x40\x00\x00\x00\x00', 1)  # <-- 5A, RESET

    def openApplication(self, check=True):
        i = 0
        tmp_ftype = []
        tmp_addr = []
        tmp_size = []
        tmp_app_data = []

        for firmware in self.firmware:
            firmware.seek(0x18)
            tmp_ftype.append(struct.unpack("<H", firmware.read(2))[0])
            firmware.seek(0x1c)
            tmp_addr.append(struct.unpack("<I", firmware.read(4))[0])
            tmp_size.append(struct.unpack("<I", firmware.read(4))[0])
            firmware.seek(0)
            tmp_app_data.append(firmware.read())
            app_size = len(tmp_app_data[i])
            ASSERT(tmp_size[i] == app_size, "APP: Size mismatch")
            if app_size < 0x40:
                ERROR("APP: Invalid size.")
            if check == True:
                if tmp_app_data[i][:3].decode() != "MMM":
                    ERROR("APP: Invalid header 'MMM' expected.")
                if tmp_app_data[i][8:17].decode() != "FILE_INFO":
                    ERROR("APP: Invalid header 'FILE_INFO' expected.")
            i += 1

        # Sort by address
        addr = tmp_addr.copy()
        size = []
        ftype = []
        app_data = []
        addr.sort()
        for start_addr in addr:
            i = 0
            for appaddr in tmp_addr:
                if appaddr == start_addr:
                    size.append(tmp_size[i])
                    ftype.append(tmp_ftype[i])
                    app_data.append(tmp_app_data[i])
                    break
                i += 1

        return app_data, addr, size, ftype

    def uploadApplication(self):
        self.da_mem(self.app_address, self.app_size, self.app_type, len(self.firmware))
        app_sz_total = 0
        for app_sz in self.app_size:
            app_sz_total += app_sz
        self.pb.reset("Download Firmware", app_sz_total)
        self.da_write()
        self.da_write_data(self.app_data)
        self.pb.end()

    def formatFAT(self):
        self.send(DA_FORMAT_FAT + b'\x00\x01')
        self.send(NONE, 4) # 00000000
        fat_addr = struct.unpack(">I", self.send(NONE, 4))[0]
        fat_len = struct.unpack(">I", self.send(NONE, 4))[0]
        self.send(NONE, 16)
        ASSERT(self.send(NONE, 2) == ACK + ACK, "Format FAT ack failed")
        self.pb.reset("Format Fat [0x%08x : 0x%08x]" % (fat_addr, fat_addr + fat_len - 1))
        self.pb.update(0)
        start_time = time.time()
        pre = 0
        while (time.time() - start_time) < 20:
            self.send(NONE, 4)
            curr = self.send(NONE, 1)[0]
            self.pb.update(curr - pre)
            pre = curr
            self.send(ACK)
            if (curr == 100):
                break
        self.pb.end()

    def da_finish(self):
        self.send(DA_FINISH, 1) # ACK
        self.send(b"\x00\x00\x00\x00", 1) # NAK


######################################################################

class ArgsFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
    pass


def upload_app(flasher):
    flasher.app_data, flasher.app_address, flasher.app_size, flasher.app_type = flasher.openApplication(True)
    flasher.open()
    flasher.connect()
    flasher.da_start()
    flasher.da_changebaud(flasher.baud)
    flasher.uploadApplication()
    if flasher.opt == 0:
        flasher.formatFAT()
    if (flasher.no_reset):
        flasher.da_finish()
    else:
        flasher.da_reset()

if __name__ == '__main__':
    flasher = MT6261()
    parser = argparse.ArgumentParser(description='MT6261/MT2503 Flash Tool', formatter_class=ArgsFormatter)
    parser.add_argument("-p", "--port", required=True, help="Serial port for flashing.")
    parser.add_argument("-b", "--baud", type=int, default=460800, help="Serial port baudrate.")
    parser.add_argument("-o", "--opt", type=int, default=1,
            help="""Flash Options:
    0: Download Firmware and Format
    1: Download Firmware only""")
    parser.add_argument("-n", "--no-reset", help="Do not reset after flashing", action='store_true')
    parser.add_argument("firmware", nargs="+", type=argparse.FileType('rb'), help="Firmware binary file.")
    parser.add_argument("-v", "--version", action="version", version="MT6261/MT2503 Flash Tool v" + APP_VER)
    parser.parse_args(namespace=flasher)
    upload_app(flasher)
