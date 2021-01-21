import struct
import sys


from unicorn import *
from unicorn.x86_const import *
import unicorn_loader

from got import *

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

returns = {}
fd_global = {}
fd_high = 10

uc = unicorn_loader.AflUnicornEngine("MemoryDump",debug_print=False)
uc_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=True)


def hook_mem_read_invalid(uc,access,address,size,value,user_data):
    uc.dump_regs()
    eip = uc.reg_read(UC_X86_REG_EIP)
    edx = uc.reg_read(UC_X86_REG_EDX)
    print("eip at invalid read = "+hex(eip))
    print("edx at invalid read = "+hex(edx))
    print("size = "+hex(size))

def hook_instruction(uc,address,size,user_data):
    global uc_heap
    if address in libc:
        print("call "+libc[address])
        ret = struct.unpack("<I",uc.mem_read(uc.reg_read(UC_X86_REG_ESP) , 4))[0]
        returns.update({ret : libc[address]})
    elif address in returns:
        print("returning from "+returns[address])
        returns.pop(address)
    if uc.mem_read(address,2) == bytearray(b'\xcd\x80'):
        print("syscall at "+hex(address))
    if address == functions["malloc"]:
        hsize = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4))[0]
        retval = uc_heap.malloc(hsize)
        uc.reg_write(UC_X86_REG_EAX, retval)
        uc.reg_write(UC_X86_REG_EIP, struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4))[0])
        uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)
    elif address == functions["posix_memalign"]:
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
    elif address == functions["writev"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        fd = struct.unpack("<I",uc.mem_read(esp + 4,4))[0]
        iov = struct.unpack("<I",uc.mem_read(esp + 8,4))[0]
        iovcnt = struct.unpack("<I",uc.mem_read(esp + 12,4))[0]
        data = struct.unpack("<I",uc.mem_read(iov,4))[0]
        datalen = struct.unpack("<I",uc.mem_read(iov + 4,4))[0]
        datastr = uc.mem_read(data,datalen)
        print("write "+str(datastr)+" "+str(iovcnt)+" times into "+str(fd))
        uc.reg_write(UC_X86_REG_EAX,iovcnt*datalen)
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["shutdown"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        print("shutdown "+str(struct.unpack("<I",uc.mem_read(esp + 4,4))[0]))
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["epoll_wait"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        print("wait on "+str(struct.unpack("<I",uc.mem_read(esp + 4,4))[0]))
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["__xstat64"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        ver = struct.unpack("<I",uc.mem_read(esp + 4,4))[0]
        path_addr = struct.unpack("<I",uc.mem_read(esp + 8,4))[0]
        path = ""
        c = struct.unpack("B",uc.mem_read(path_addr,1))[0]
        path_addr += 1
        while c != 0:
            path += chr(c)
            c = struct.unpack("B",uc.mem_read(path_addr,1))[0]
            path_addr += 1
        print("calling __xstat64 with "+str(ver)+" on "+str(path))
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["__fxstat64"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        ver = struct.unpack("<I",uc.mem_read(esp + 4,4))[0]
        fd = struct.unpack("<I",uc.mem_read(esp+8,4))[0]
        print("calling __fxstat64 with "+str(ver)+" on "+str(fd))
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["open64"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        path_addr = struct.unpack("<I",uc.mem_read(esp+4,4))[0]
        path = ""
        c = struct.unpack("B",uc.mem_read(path_addr,1))[0]
        path_addr += 1
        while c != 0:
            path += chr(c)
            c = struct.unpack("B",uc.mem_read(path_addr,1))[0]
            path_addr += 1
        flags = struct.unpack("<I",uc.mem_read(esp+8,4))[0]
        print("calling open on "+str(path)+" with "+str(flags)+" as flags")
        global fd_high
        global fd_global
        fd_high += 1
        print("opening "+str(path)+" to fd "+str(fd_high))
        if flags | 1:
            fd_global.update({fd_high: open(path,"wb")})
        elif flags | 2:
            fd_global.update({fd_high: open(path,"rwb")})
        elif flags | 1024:
            fd_global.update({fd_high: open(path,"ab")})
        else:
            fd_global.update({fd_high: open(path,"r")})
        uc.reg_write(UC_X86_REG_EAX,fd_high)
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["fcntl64"]:
        # Herausfinden was die cmds bedeuten etc.
        esp = uc.reg_read(UC_X86_REG_ESP)
        fd = struct.unpack("<I",uc.mem_read(esp+4,4))[0]
        cmd = struct.unpack("<I",uc.mem_read(esp+8,4))[0]
        print("fcntl on "+str(fd)+" with cmd "+str(cmd))
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)
    elif address == functions["write"]:
        esp = uc.reg_read(UC_X86_REG_ESP)
        fd = struct.unpack("<I",uc.mem_read(esp+4,4))[0]
        buf = struct.unpack("<I",uc.mem_read(esp+8,4))[0]
        count = struct.unpack("<I",uc.mem_read(esp+12,4))[0]
        writen = uc.mem_read(buf,count)
        print("write into "+str(fd))
        print(writen)
        uc.reg_write(UC_X86_REG_EAX,count)
        uc.reg_write(UC_X86_REG_EIP,struct.unpack("<I",uc.mem_read(esp,4))[0])
        uc.reg_write(UC_X86_REG_ESP,esp+4)


            
        









    global ins
    #print(hex(address))
    ins += 1




uc.hook_add(UC_HOOK_MEM_READ_INVALID,hook_mem_read_invalid)
uc.hook_add(UC_HOOK_CODE,hook_instruction)


START_ADDRESS = 0x5662897c
START2_ADDRESS = 0x5662897f
SIZE = 0x400
BUF = 0x56819020
CALLER_RET=0x5667dce3
FILENAME = "sample"
POSIX_MEMALIGN = 0xf7da4aa0
MALLOC=0xf7fed4d0
WRITEV=0x565695d6
SHUTDOWN=0x56569896
EPOLL_WAIT=0xf7e225d0

with open(FILENAME,"rb") as f:
    request = f.read()

uc.mem_write(BUF,request[:SIZE])
uc.reg_write(UC_X86_REG_EAX,len(request[:SIZE]))
print("eax = "+str(len(request[:SIZE])))

uc.emu_start(START_ADDRESS,0,0,count=1)
try:
    # bricht in malloc ab, beim Benutzen von gs
    uc.emu_start(START2_ADDRESS,CALLER_RET,timeout=0,count=0)
except UcError as e:
    print(ins)
    uc.force_crash(e)
	
