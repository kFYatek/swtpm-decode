#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import struct
import sys
import typing


def decode_libtpms_persistent_all(data: bytes):
    print(data)
    raise Exception('Not yet implemented')


def decode_blob(data: bytes):
    offset = 0

    class TlvHeader(typing.NamedTuple):
        tag: int
        length: int

    tlvheader_str = struct.Struct('!HL')

    class BlobHeader(typing.NamedTuple):
        version: int
        min_version: int
        hdrsize: int
        flags: int
        totlen: int

    blobheader_str = struct.Struct('!BBHHL')
    bh = BlobHeader(*blobheader_str.unpack_from(data, offset))
    offset += blobheader_str.size
    if bh.totlen != len(data) or bh.hdrsize != blobheader_str.size:
        raise Exception('Broken blob header')
    if bh.min_version > 2:
        raise Exception('Unsupported version')
    match bh.version:
        case 1:
            return decode_libtpms_persistent_all(data[offset:])
        case 2:
            while offset < len(data):
                tlvhdr = TlvHeader(*tlvheader_str.unpack_from(data, offset))
                offset += tlvheader_str.size
                if tlvhdr.tag == 1:
                    assert offset + tlvhdr.length <= len(data)
                    return decode_libtpms_persistent_all(data[offset:offset + tlvhdr.length])
                else:
                    offset += tlvhdr.length
            raise Exception('Unencrypted data not found in the file')
        case _:
            raise Exception('Unsupported version')


def decode_data(data: bytes):
    offset = 0
    globalheader_str = struct.Struct('=QBBH')
    magic, version, _padding, hdrsize = globalheader_str.unpack_from(data, offset)
    offset += globalheader_str.size
    if magic != 0x737774706d6c696e:
        raise Exception('Invalid magic')
    if version != 1:
        raise Exception('Invalid version')

    class FileHeader(typing.NamedTuple):
        offset: int
        data_length: int
        section_length: int

    fileheader_str = struct.Struct('=LLL')
    fileheaders = []
    while offset < hdrsize:
        fileheaders.append(FileHeader(*fileheader_str.unpack_from(data, offset)))
        offset += fileheader_str.size
    assert offset == hdrsize
    i = 0
    while i < len(fileheaders):
        if fileheaders[i].offset == 0:
            del fileheaders[i]
        else:
            i += 1
    if len(fileheaders) != 1:
        raise Exception('Only SWTPM files with exactly one blob are supported')
    return decode_blob(
        data[fileheaders[0].offset:fileheaders[0].offset + fileheaders[0].data_length])


def decode_file(filename: str):
    with open(filename, 'rb') as f:
        return decode_data(f.read())


def _main(*args):
    parser = argparse.ArgumentParser(description='Decode a SWTPM linear persistence file.')
    parser.add_argument('tpmdata', type=str, help='Input file')
    args = parser.parse_args(args)
    json.dump(decode_file(args.tpmdata), sys.stdout, indent=4)


if __name__ == '__main__':
    sys.exit(_main(*sys.argv[1:]))
