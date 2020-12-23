import struct

from unicorn import *
from unicorn.x86_const import *
import unicorn_loader

def hook_syscall(uc,user_data):
	eax = uc.reg_read(UC_X86_REG_EAX)
	print("eax = "+hex(eax))
	exit(0)

def hook_mem_read_invalid(uc,access,address,size,value,user_data):
	eip = uc.reg_read(UC_X86_REG_EIP)
	print("eip at invalid read = "+hex(eip))
	print("size = "+hex(size))


uc = unicorn_loader.AflUnicornEngine("MemoryDump",debug_print=False)

uc.hook_add(UC_HOOK_INSN,hook_syscall,arg1=UC_X86_INS_SYSCALL)
uc.hook_add(UC_HOOK_MEM_READ_INVALID,hook_mem_read_invalid)

eip = uc.reg_read(UC_X86_REG_EIP)
print("feip = "+hex(eip))
uc.emu_start(eip,0,0,count=1)

eip = uc.reg_read(UC_X86_REG_EIP)
print("starteip = "+hex(eip))
uc.emu_start(eip,0,timeout=0,count=0)
