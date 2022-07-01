import binascii
from base64 import b64decode
import struct

from qiling.os.windows.fncc import *
from qiling import *

import argparse

@winsdkapi(cc=STDCALL)
def hook_chkstk(ql, addr, params):
	return ql.arch.regs.rax

def parse_args():
	parser = argparse.ArgumentParser(description="decrypts a ClepV4 encrypted device key.")
	parser.add_argument("--license", required=True, help="base64 encoded encrypted device license (Required length: 4094)")
	parser.add_argument("--smbios", required=True, help="base64 encoded SMBIOS system struct.")
	parser.add_argument("--driveser", required=True, help="base64 encoded null-terminated root drive serial number.")
	args = parser.parse_args()
	return (args.license, args.smbios, args.driveser)

if __name__ == '__main__':
	enc_license_b64, smbios_b64, driveser_b64 = parse_args()
	encrypted_device_license = b64decode(enc_license_b64)
	smbiosSystem = b64decode(smbios_b64)
	driveSer = b64decode(driveser_b64)

	assert len(encrypted_device_license) == 4094, "Error: Encrypted Device License length mismatch. (Expected: 4094)"

	max_smbios = 256
	max_driveser = 64
	max_tpminfo = 901

	if (len(smbiosSystem) > max_smbios):
		smbiosSystem = smbiosSystem[:max_smbios]

	if (len(driveSer) > max_driveser):
		driveSer = driveSer[:max_driveser]

	ql = Qiling(["./clipsp.sys"], ".\\x8664_windows", libcache=True, console=False)

	ql.os.set_api("__chkstk", hook_chkstk)

	clep_vault_func_pattern = b"\x4C\x8B\xDC\x49\x89\x4B\x08"
	clep_vault_size = 0x4e
	clep_vault_func = ql.mem.search(clep_vault_func_pattern, begin=0x1c0000000, end=0x1d0000000)[0]
	if clep_vault_func is None:
		print("Error: Failed to find vault function using pattern.")
		exit()

	# Gets the cached request memory location through a bit of trickery:
	# Basically pattern matching a part of a vault function, navigating to the lea request opcode, then reading the operand for the offset
	clep_request_pattern = b"\xC6\x45\x00\x19\x8A\x45\x00\x8B\x04\x24\x48\x83\xEC\x10\x8B\x04\x24\x8B\x04\x24\x48\x83\xEC\x50\x48\x8D\x4C\x24\x20\x8B\x01\x41\x0F\x10\x02\x33\xC0\x48\x8D\x59\x0F\x48\x83\xE3\xF0\xF3\x0F\x7F\x43\x28"
	clep_request_opcode_offset = 0x4e # actually 0x4b, but + 3 to get the operand directly
	clep_request_func = ql.mem.search(clep_request_pattern, begin=0x1c0000000, end=0x1d0000000)[0]
	if clep_request_func is None:
		print("Error: Failed to find request function using pattern.")
		exit()

	clep_request_opcode = clep_request_func + clep_request_opcode_offset
	clep_request_ptr_offset = struct.unpack("<I", ql.mem.read(clep_request_opcode, 4))[0]
	clep_request_ptr = clep_request_opcode + clep_request_ptr_offset + 4 # To offset the operand size

	req_version = clep_request_ptr
	req_smbios = req_version + 4
	req_driveser = req_smbios + max_smbios
	req_tpmstatus = req_driveser + max_driveser
	req_tpminfo = req_tpmstatus + 1
	req_istogo = req_tpminfo + max_tpminfo
	req_debuggerEnabled = req_istogo + 1
	req_debuggerAttached = req_debuggerEnabled + 4
	req_remdata = req_debuggerAttached + 4

	ql.mem.write(req_version, struct.pack("<I", 0x4))
	ql.mem.write(req_smbios, smbiosSystem)
	ql.mem.write(req_driveser, driveSer)

	ql.mem.write(req_tpmstatus, struct.pack("<B", 0x0))
	ql.mem.write(req_istogo, struct.pack("<B", 0x0))

	ql.mem.write(req_debuggerEnabled, struct.pack("<I", 0x7ffe02d4))
	ql.mem.write(req_debuggerAttached, struct.pack("<I", 0x7ffe02d4))

	ql.mem.map(0x7ffe02d4 // 4096*4096, 4096)
	ql.mem.write(0x7ffe02d4, struct.pack("<I", 0x00000010)) # 0x0 - Debugger not enabled | 0x10 - Debugger not attached

	pb_secret = ql.os.heap.alloc(32)
	license_buffer = ql.os.heap.alloc(len(encrypted_device_license))
	ql.mem.write(license_buffer, encrypted_device_license)

	# sp_cache = 0x1C0043600 --- If needed this could also be done through pattern matching, but we can just use our own buffer
	sp_cache = ql.os.heap.alloc(64)

	#clep_vault_v4_begin = 0x1C000B234
	#clep_vault_v4_end = 0x1C000B282

	ql.arch.regs.rcx = 0x0
	ql.arch.regs.rdx = license_buffer + 4
	ql.arch.regs.r8 = pb_secret
	ql.arch.regs.r9 = license_buffer + 516

	ql.stack_write(0x30, sp_cache)

	ql.run(begin=clep_vault_func, end=clep_vault_func + clep_vault_size)

	buffer = ql.mem.read(pb_secret, 16)
	print(binascii.hexlify(buffer).decode("utf-8"))
