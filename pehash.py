#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pehash, Portable Executable hash of structural properties

@author: AnyMaster
"""
__version__ = '1.0.0'
__author__ = 'AnyMaster'

import sys
import hashlib
from bz2 import compress

from pefile import PE
from bitstring import pack, BitArray


def get_pehash(file_name):
    """ Return pehash for PE file, sha1 of PE structural properties.
    """

    exe = PE(file_name)

    # Image Characteristics
    img_chars = pack('uint:16', exe.FILE_HEADER.Characteristics)
    pehash_bin = BitArray(img_chars[0:8] ^ img_chars[8:16])

    # Subsystem
    sub_chars = pack('uint:16', exe.FILE_HEADER.Machine)
    pehash_bin.append(sub_chars[0:8] ^ sub_chars[8:16])

    # Stack Commit Size, rounded up to a value divisible by 4096,
    # Windows page boundary, 8 lower bits must be discarded
    stack_commit = exe.OPTIONAL_HEADER.SizeOfStackCommit
    if stack_commit % 4096:
        stack_commit += 4096 - stack_commit % 4096
    stack_commit = pack('uint:24', stack_commit >> 8)
    pehash_bin.append(
        stack_commit[:8] ^ stack_commit[8:16] ^ stack_commit[16:24])


    # Heap Commit Size, rounded up to page boundary size,
    # 8 lower bits must be discarded
    heap_commit = exe.OPTIONAL_HEADER.SizeOfHeapCommit
    if heap_commit % 4096:
        heap_commit += 4096 - heap_commit % 4096
    heap_commit = pack('uint:24', heap_commit >> 8)
    pehash_bin.append(heap_commit[:8] ^ heap_commit[8:16] ^ heap_commit[16:24])

    # Section structural information
    for section in exe.sections:
        # virtual address, 9 lower bits must be discarded
        pehash_bin.append(pack('uint:24', section.VirtualAddress >> 9))

        # raw size, 8 lower bits must be discarded
        pehash_bin.append(pack('uint:24', section.SizeOfRawData >> 8))

        # section chars, 16 lower bits must be discarded
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
    return hashlib.sha1(pehash_bin.tobytes()).hexdigest()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Error: no file specified"
        sys.exit(0)
    print get_pehash(sys.argv[1]), sys.argv[1]
