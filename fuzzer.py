import struct
import sys


from unicorn import *
from unicorn.x86_const import *
import unicorn_loader

ins = 0

breaks = { 
	0xf7dbc970 : "memset" ,
	0xf7dbcce0 : "memcpy" ,
	0xf7dbbb00 : "strncmp" ,
	0xf7e23210 : "__xstat64" ,
	0xf7f9cd90 : "open64" ,
	0xf7e23240 : "__fxstat64" ,
	0xf7e2d790 : "writev" ,
	0xf7f9c380 : "write" ,
	0xf7f9c4e0 : "close" ,
	0xf7fed290 : "free" ,
	0xf7f9c810 : "send"
}

uc = unicorn_loader.AflUnicornEngine("MemoryDump",debug_print=False)
uc_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=True)

def hook_syscall(uc,user_data):
	eax = uc.reg_read(UC_X86_REG_EAX)
	print("syscall")
	print("eax = "+hex(eax))
	exit(0)

def hook_mem_read_invalid(uc,access,address,size,value,user_data):
	uc.dump_regs()
	eip = uc.reg_read(UC_X86_REG_EIP)
	edx = uc.reg_read(UC_X86_REG_EDX)
	print("eip at invalid read = "+hex(eip))
	print("edx at invalid read = "+hex(edx))
	print("size = "+hex(size))

def hook_instruction(uc,address,size,user_data):
	global uc_heap
	if uc.mem_read(address,2) == bytearray(b'\xcd\x80'):
		print("syscall at "+hex(address))
	if address in breaks:
		print(breaks[address])
	elif address == MALLOC:
		hsize = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4))[0]
		retval = uc_heap.malloc(hsize)
		uc.reg_write(UC_X86_REG_EAX, retval)
		uc.reg_write(UC_X86_REG_EIP, struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4))[0])
		uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)
	elif address == POSIX_MEMALIGN:
		memptr = struct.unpack("<I",uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4,4))[0]
		alignment = struct.unpack("<I",uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8,4))[0]
		hsize = struct.unpack("<I",uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 12,4))[0]
		nsize = hsize + alignment
		ptr = uc_heap.malloc(nsize)
		if hsize <= nsize - (alignment - (ptr % alignment)):
			ptr = ptr + (alignment - (ptr % alignment))
			print("posix worked fine, address = "+hex(ptr)+" ,alignment = "+hex(alignment))
			uc.reg_write(UC_X86_REG_EAX,0)
			uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(uc.reg_read(UC_X86_REG_ESP),4))[0])
			uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)
			uc.mem_write(memptr,struct.pack("<I",ptr))
		else:
			print("something in posix_memalign went wrong")
			exit(0)



	global ins
	#print(hex(address))
	ins += 1




uc.hook_add(UC_HOOK_INSN,hook_syscall,arg1=UC_X86_INS_SYSCALL)
uc.hook_add(UC_HOOK_MEM_READ_INVALID,hook_mem_read_invalid)
uc.hook_add(UC_HOOK_CODE,hook_instruction)


START_ADDRESS = 0x56586c11
START2_ADDRESS = 0x56586c13
START_ADDRESS_AFL = 0x5662b618
START2_ADDRESS_AFL = 0x5662b61d
SIZE = 0x400
BUF_AFL = 0x56813e00
BUF = 0x56637e00
NGX_UNIX_SEND = 0x56587097
NGX_UNIX_SEND_AFL = 0x5662cf60
FILENAME = "sample"
POSIX_MEMALIGN = 0xf7db96d0
MALLOC=0xf7fed140

with open(FILENAME,"rb") as f:
	request = f.read()

uc.mem_write(BUF,request[:SIZE])
uc.reg_write(UC_X86_REG_EAX,len(request[:SIZE]))
print("eax = "+str(len(request[:SIZE])))

uc.emu_start(START_ADDRESS,0,0,count=1)
try:
	# bricht in malloc ab, beim Benutzen von gs
	uc.emu_start(START2_ADDRESS,NGX_UNIX_SEND,timeout=0,count=0)
except UcError as e:
	print(ins)
	uc.force_crash(e)
	
