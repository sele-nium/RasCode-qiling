#!/usr/bin/env python3
#
# thanks to drsnooker on hashkiller forums for all informations, support and reverse of rascode
#

import argparse
from qiling.core import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT, QL_ARCH, QL_ENDIAN, QL_OS
from qiling.os.const import STRING

LENBUFFER = 72
LENPASSWORD = 10
# all these addresses are relative to begin
ADDR_GET_PASSWORD = 0x14a8c
ADDR_GET_MACADDRESS = 0x17EDC
ADDR_GET_SERIALNMBER = 0x34DAC
ADDR_GEN_PASSWORD_START = 0x14978
ADDR_GEN_PASSWORD_END = 0x14a90

def get_password(ql: Qiling):
    password = ql.mem.read(ql.arch.regs.sp+0xe8, LENPASSWORD) # read the memory where the password has been written
    print("Password: " + password.decode("ascii"))

def get_MAC(ql: Qiling):
    # mac address in this router is not used for calculate the default password
    mac = b'\x11\x22\x33\x44\x55\x66'

    mac_addr = ql.os.heap.alloc(len(mac))  # allocate buffer
    ql.mem.write(mac_addr, mac)            # write mac address in buffer

    ql.arch.regs.v0 = mac_addr             # set register with address of allocated buffer
    ql.arch.regs.arch_pc = ql.arch.regs.ra # return from call
                                           # ra register has the address before jump

def get_Serial(ql: Qiling):
    serial = serial_number.encode('ascii')

    serial_addr = ql.os.heap.alloc(0x14)    # allocate buffer
    ql.mem.write(serial_addr, serial)       # write serial in buffer

    ql.arch.regs.v0 = serial_addr           # set register with address of allocated buffer

    ql.arch.regs.arch_pc = ql.arch.regs.ra  # return from call
                                            # ra register has the address before jump

def partial_run_init(ql: Qiling):
    # prepare arguments for function FUN_80034978 (ghidra name)
    buff_addr = ql.os.heap.alloc(LENBUFFER)  # allocate buffer
    ql.arch.regs.a0 = buff_addr              # set register with address of allocated buffer
    ql.arch.regs.a1 = LENPASSWORD;           # set len password

def main():
    global serial_number

    parser = argparse.ArgumentParser(description='Qiling script for run rascode in emulated enviroment')
    parser.add_argument('--serial', help='Serial number', required=True)
    parser.add_argument('--firmware', help='Firmware file default is RasCode_d0', default='RasCode_d0')
    parser.add_argument('--disasm', help='Show assembler code while running', action='store_true')
    parser.add_argument('--debug', help='Enable debug server', action='store_true')
    parser.add_argument('--host', help='Bind address of debug server', default='127.0.0.1')
    parser.add_argument('--port', help='Port debug server', default='10000')
    args = parser.parse_args()

    serial_number = args.serial

    try:
        with open(args.firmware, "rb") as f:
            abRasCode = f.read()
    except FileNotFoundError as err:
        print(err)
        return

    ql = Qiling(code=abRasCode, archtype=QL_ARCH.MIPS, endian=QL_ENDIAN.EB, ostype=QL_OS.BLOB, profile="rascode.ql", verbose=QL_VERBOSE.DISASM if args.disasm else QL_VERBOSE.DEBUG)

    image_base_addr = ql.loader.load_address

    if args.debug:
        ql.debugger = f"gdb:{args.host}:{args.port}"
        print(f"Base Address 0x{image_base_addr:0>4X}")

    # hook addresses for control the running emulation
    ql.hook_address(get_password, image_base_addr + ADDR_GET_PASSWORD)
    ql.hook_address(get_MAC, image_base_addr + ADDR_GET_MACADDRESS)
    ql.hook_address(get_Serial, image_base_addr + ADDR_GET_SERIALNMBER)

    partial_run_init(ql)

    ql.run(image_base_addr + ADDR_GEN_PASSWORD_START, image_base_addr + ADDR_GEN_PASSWORD_END)

if __name__ == "__main__":
    main()
