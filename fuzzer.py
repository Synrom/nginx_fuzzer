import struct

from unicorn import *
from unicorn.x86_const import *
import unicorn_loader

def hook_syscall(uc,user_data):
	eax = uc.reg_read(UC_X86_REG_EAX)
	print("eax = "+hex(eax))
	exit(0)

uc = unicorn_loader.AflUnicornEngine("MemoryDump",debug_print=True)

uc.hook_add(UC_HOOK_INSN,hook_syscall,arg1=UC_X86_INS_SYSCALL)

eip = uc.reg_read(UC_X86_REG_EIP)
uc.emu_start(eip,0,0,count=1)

eip = uc.reg_read(UC_X86_REG_EIP)
uc.emu_start(eip,0,timeout=0,count=0)
