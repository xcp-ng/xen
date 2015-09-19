#!/usr/bin/env python3
import binascii
import struct
import sys
import subprocess
import re

# Decode a certificate into a format suitable for embedding in Xen.

out = subprocess.check_output(['openssl', 'rsa', '-pubin', '-inform', 'PEM',
                               '-noout', '-text'], stdin=sys.stdin,
                               universal_newlines=True)
combined = ''
for line in out.split('\n'):
    line = line.rstrip()
    if line.startswith("    "):
        combined += line.strip().replace(':', '')
    match = re.match(r"Exponent: .* \(0x(.*)\)", line)
    if match:
        e = match.group(1)

n = combined.lstrip('0')
if len(n) % 2 == 1:
    n = '0' + n
n = binascii.unhexlify(n)
e = e.lstrip('0')
if len(e) % 2 == 1:
    e = '0' + e
e = binascii.unhexlify(e)

sys.stdout.buffer.write(struct.pack('I', len(n)))
sys.stdout.buffer.write(n)
sys.stdout.buffer.write(struct.pack('I', len(e)))
sys.stdout.buffer.write(e)
