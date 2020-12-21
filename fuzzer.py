import struct

from unicorn import *
from unicorn.x86_const import *
import unicorn_loader

uc = unicorn_loader.AflUnicornEngine("MemoryDump",debug_print=True)
