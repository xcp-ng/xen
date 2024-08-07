#!/usr/bin/python

from __future__ import print_function

import sys, re
from structs import unions, structs, defines

# command line arguments
arch    = sys.argv[1]
outfile = sys.argv[2]
infiles = sys.argv[3:]


###########################################################################
# configuration #2: architecture information

inttypes = {}
header = {}
footer = {}

#arm
inttypes["arm32"] = [
    ("unsigned long", "__danger_unsigned_long_on_arm32"),
    ("long",          "__danger_long_on_arm32"),
    ("xen_pfn_t",     "uint64_t"),
    ("xen_ulong_t",   "uint64_t"),
    ("uint64_t",      "__align8__ uint64_t"),
]
header["arm32"] = """
#define __arm___ARM32 1
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(n64, n32) union { uint64_t n64; uint32_t n32; }
# define __align8__ __attribute__((aligned (8)))
#else
# define __DECL_REG(n64, n32) uint64_t n64
# define __align8__ FIXME
#endif
"""
footer["arm32"] = """
#undef __DECL_REG
"""

inttypes["arm64"] = [
    ("unsigned long", "__danger_unsigned_long_on_arm64"),
    ("long",          "__danger_long_on_arm64"),
    ("xen_pfn_t",     "uint64_t"),
    ("xen_ulong_t",   "uint64_t"),
    ("uint64_t",      "__align8__ uint64_t"),
]
header["arm64"] = """
#define __aarch64___ARM64 1
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(n64, n32) union { uint64_t n64; uint32_t n32; }
# define __align8__ __attribute__((aligned (8)))
#else
# define __DECL_REG(n64, n32) uint64_t n64
# define __align8__ FIXME
#endif
"""
footer["arm64"] = """
#undef __DECL_REG
"""

# x86_32
inttypes["x86_32"] = [
    ("unsigned long", "uint32_t"),
    ("long",          "uint32_t"),
    ("xen_pfn_t",     "uint32_t"),
    ("xen_ulong_t",   "uint32_t"),
]
header["x86_32"] = """
#define __DECL_REG_LO8(which) uint32_t e ## which ## x
#define __DECL_REG_LO16(name) uint32_t e ## name
#define __i386___X86_32 1
#pragma pack(4)
"""
footer["x86_32"] = """
#undef __DECL_REG_LO8
#undef __DECL_REG_LO16
#pragma pack()
"""

# x86_64
inttypes["x86_64"] = [
    ("unsigned long", "__align8__ uint64_t"),
    ("long",          "__align8__ uint64_t"),
    ("xen_pfn_t",     "__align8__ uint64_t"),
    ("xen_ulong_t",   "__align8__ uint64_t"),
]
header["x86_64"] = """
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(name) union { uint64_t r ## name, e ## name; }
# define __align8__ __attribute__((aligned (8)))
#else
# define __DECL_REG(name) uint64_t r ## name
# define __align8__ FIXME
#endif
#define __DECL_REG_LOHI(name) __DECL_REG(name ## x)
#define __DECL_REG_LO8        __DECL_REG
#define __DECL_REG_LO16       __DECL_REG
#define __DECL_REG_HI         __DECL_REG
#define __x86_64___X86_64 1
"""
footer["x86_64"] = """
#undef __DECL_REG
#undef __DECL_REG_LOHI
#undef __DECL_REG_LO8
#undef __DECL_REG_LO16
#undef __DECL_REG_HI
"""

###########################################################################
# main

input  = ""
output = ""
fileid = re.sub("[-.]", "_", "__FOREIGN_%s__" % outfile.upper())

for name in infiles:
    f = open(name, "r")

    # Sanity check the licence of the input file(s)
    line = f.readline()
    if line != "/* SPDX-License-Identifier: MIT */\n":
        print("Error: %s %s Missing or unexpected SPDX tag '%s'" %
              (sys.argv[0], name, line.strip()), file=sys.stderr)
        exit(1)

    input += f.read()
    f.close()

# replace path in "infiles" by path in '/usr/include' to avoid exposing the
# build directory path in the generated headers.
headers_name_list = ""
public_headers_location = 'xen/include/public/'
for name in infiles:
    i = name.rindex(public_headers_location)
    i += len(public_headers_location)
    headers_name_list += " xen/%s" % (name[i:])

# add header
output += """/* SPDX-License-Identifier: MIT */
/*
 * public xen defines and struct for %s
 * generated from%s by %s -- DO NOT EDIT
 */

#ifndef %s
#define %s 1

""" % (arch, headers_name_list, sys.argv[0], fileid, fileid)

if arch in header:
    output += header[arch]
    output += "\n"

defined = {}

# add defines to output
for line in re.findall("#define[^\n]+", input):
    for define in defines:
        regex = r"#define\s+%s\b" % define
        match = re.search(regex, line)
        if None == match:
            continue
        defined[define] = 1
        if define.upper()[0] == define[0]:
            replace = define + "_" + arch.upper()
        else:
            replace = define + "_" + arch
        regex = r"\b%s\b" % define
        output += re.sub(regex, replace, line) + "\n"
output += "\n"

# delete defines, comments, empty lines
input = re.sub("#define[^\n]+\n", "", input)
input = re.compile(r"/\*(.*?)\*/", re.S).sub("", input)
input = re.compile(r"\n\s*\n", re.S).sub("\n", input)

# add unions to output
for union in unions:
    regex = r"union\s+%s\s*\{(.*?)\n\};" % union
    match = re.search(regex, input, re.S)
    if None == match:
        output += "#define %s_has_no_%s 1\n" % (arch, union)
    else:
        output += "union %s_%s {%s\n};\n" % (union, arch, match.group(1))
    output += "\n"

# add structs to output
for struct in structs:
    regex = r"(?:#ifdef ([A-Z_]+))?\nstruct\s+%s\s*\{(.*?)\n\};" % struct
    match = re.search(regex, input, re.S)
    if None == match or \
           (match.group(1) is not None and match.group(1) not in defined):
        output += "#define %s_has_no_%s 1\n" % (arch, struct)
    else:
        output += "struct %s_%s {%s\n};\n" % (struct, arch, match.group(2))
        output += "typedef struct %s_%s %s_%s_t;\n" % (struct, arch, struct, arch)
    output += "\n"

# add footer
if arch in footer:
    output += footer[arch]
    output += "\n"
output += "#endif /* %s */\n" % fileid

# replace: defines
for define in defines:
    if define.upper()[0] == define[0]:
        replace = define + "_" + arch.upper()
    else:
        replace = define + "_" + arch
    output = re.sub(r"\b%s\b" % define, replace, output)

# replace: unions
for union in unions:
    output = re.sub(r"\b(union\s+%s)\b" % union, r"\1_%s" % arch, output)

# replace: structs + struct typedefs
for struct in structs:
    output = re.sub(r"\b(struct\s+%s)\b" % struct, r"\1_%s" % arch, output)
    output = re.sub(r"\b(%s)_t\b" % struct, r"\1_%s_t" % arch, output)

# replace: integer types
for old, new in inttypes[arch]:
    output = re.sub(r"\b%s\b" % old, new, output)

# print results
with open(outfile, "w") as f:
    f.write(output)
