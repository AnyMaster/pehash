#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pehash, Portable Executable hash of structural properties

@author: AnyMaster
"""
__version__ = '1.0.0'
__author__ = 'AnyMaster'

from hashlib import sha1
from bz2 import compress

from pefile import PE
from bitstring import pack


def get_pehash(file_name):
    """ Return pehash for PE file, sha1 of PE structural properties.
    """

    exe = PE(file_name)

    # Image Characteristics
    img_chars = pack('uint:16', exe.FILE_HEADER.Characteristics)
    pehash_bin = img_chars[0:8] ^ img_chars[8:16]

    # Subsystem
    subsystem = pack('uint:16', exe.FILE_HEADER.Machine)
    pehash_bin.append(subsystem[0:8] ^ subsystem[8:16])

    # Stack Commit Size, rounded up to a value divisible by 4096,
    # Windows page boundary, 8 lower bits must be discarded
    # in PE32+ is 8 bytes
    stack_commit = exe.OPTIONAL_HEADER.SizeOfStackCommit
    if stack_commit % 4096:
        stack_commit += 4096 - stack_commit % 4096
    stack_commit = pack('uint:56', stack_commit >> 8)
    pehash_bin.append(
        stack_commit[:8] ^ stack_commit[8:16] ^
        stack_commit[16:24] ^ stack_commit[24:32] ^
        stack_commit[32:40] ^ stack_commit[40:48] ^ stack_commit[48:56])

    # Heap Commit Size, rounded up to page boundary size,
    # 8 lower bits must be discarded
    # in PE32+ is 8 bytes
    heap_commit = exe.OPTIONAL_HEADER.SizeOfHeapCommit
    if heap_commit % 4096:
        heap_commit += 4096 - heap_commit % 4096
    heap_commit = pack('uint:56', heap_commit >> 8)
    pehash_bin.append(
        heap_commit[:8] ^ heap_commit[8:16] ^
        heap_commit[16:24] ^ heap_commit[24:32] ^
        heap_commit[32:40] ^ heap_commit[40:48] ^ heap_commit[48:56])

    # Section structural information
    for section in exe.sections:
        # Virtual Address, 9 lower bits must be discarded
        pehash_bin.append(pack('uint:24', section.VirtualAddress >> 9))

        # Size Of Raw Data, 8 lower bits must be discarded
        pehash_bin.append(pack('uint:24', section.SizeOfRawData >> 8))

        # Section Characteristics, 16 lower bits must be discarded
        sect_chars = pack('uint:16', section.Characteristics >> 16)
        pehash_bin.append(sect_chars[:8] ^ sect_chars[8:16])

        # Kolmogorov Complexity, len(Bzip2(data))/len(data)
        # (0..1} ∈ R   ->  [0..7] ⊂ N
        kolmogorov = 0
        if section.SizeOfRawData:
            kolmogorov = int(round(
                len(compress(section.get_data()))
                * 7.0 /
                section.SizeOfRawData))
            if kolmogorov > 7:
                kolmogorov = 7
        pehash_bin.append(pack('uint:8', kolmogorov))
        
    assert 0 == pehash_bin.len % 8
    return sha1(pehash_bin.tobytes()).hexdigest()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print "Error: no file specified"
        sys.exit(0)
    print get_pehash(sys.argv[1]), sys.argv[1]
