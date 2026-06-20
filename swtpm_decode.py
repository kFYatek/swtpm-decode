#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import base64
import json
import struct
import sys
import typing


class LibtpmsHeader(typing.NamedTuple):
    version: int
    magic: int
    min_version: int

    @staticmethod
    def decode(data: bytes, offset: list[int], cur_version: int, exp_magic: int) -> LibtpmsHeader:
        stru = struct.Struct('!HL')
        version, magic = stru.unpack_from(data, offset[0])
        offset[0] += stru.size
        if magic != exp_magic:
            raise Exception('Invalid magic')
        if version >= 2:
            min_version = struct.unpack_from('!H', data, offset[0])[0]
            offset[0] += 2
            if min_version > cur_version:
                raise Exception('Unsupported version')
        else:
            min_version = 0
        return LibtpmsHeader(version, magic, min_version)


def decode_libtpms_string(data: bytes, offset: list[int]) -> bytes:
    size = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += size + 2
    return data[offset[0] - size:offset[0]]


def libtpms_block_skip_read(data: bytes, offset: list[int], process):
    has_block = bool(struct.unpack_from('!B', data, offset[0])[0])
    offset[0] += 1
    blocksize = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    result = None
    if has_block:
        if process is not None:
            result = process(data[offset[0]:offset[0] + blocksize])
        offset[0] += blocksize
    return result


def decode_libtpms_compile_constants(data: bytes, offset: list[int]):
    exp_array_sizes = {1: 88, 2: 88, 3: 120}
    hdr = LibtpmsHeader.decode(data, offset, 3, 0xc9ea6431)
    array_size = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    if array_size != exp_array_sizes[hdr.version]:
        raise Exception('Invalid PACompileConstants')
    # TODO: Actually check these?
    offset[0] += 4 * array_size
    if hdr.version >= 2:
        libtpms_block_skip_read(data, offset, None)


def decode_libtpms_pcr_policies(data: bytes):
    result = []
    offset = [0]
    hdr = LibtpmsHeader.decode(data, offset, 2, 0x176be626)
    array_size = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    for i in range(array_size):
        result1 = {}
        result1['hashAlg'] = struct.unpack_from('!H', data, offset[0])[0]
        offset[0] += 2
        result1['policy'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
        result.append(result1)
    if hdr.version >= 2:
        libtpms_block_skip_read(data, offset, None)
    return result


def decode_libtpms_pcr_selection(data: bytes, offset: list[int]):
    result = []
    count = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    for i in range(count):
        result1 = {}
        result1['hash'] = struct.unpack_from('!H', data, offset[0])[0]
        offset[0] += 2
        sizeofSelect = struct.unpack_from('!B', data, offset[0])[0]
        offset[0] += 1
        result1['pcrSelect'] = base64.b64encode(data[offset[0]:offset[0] + sizeofSelect]).decode()
        offset[0] += sizeofSelect
        result.append(result1)
    return result


def decode_libtpms_persistent_data_v4(data: bytes):
    result = {}
    offset = [0]
    result['EPSeedCompatLevel'] = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1
    result['SPSeedCompatLevel'] = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1
    result['PPSeedCompatLevel'] = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1
    libtpms_block_skip_read(data, offset, None)
    return result


def decode_libtpms_persistent_data_v3(data: bytes):
    result = {}
    offset = [0]
    result['shadowPcrAllocated'] = decode_libtpms_pcr_selection(data, offset)
    result.update(libtpms_block_skip_read(data, offset, decode_libtpms_persistent_data_v4) or {})
    return result


def decode_libtpms_persistent_data(data: bytes, offset: list[int]):
    result = {}
    hdr = LibtpmsHeader.decode(data, offset, 5, 0x12213443)
    result['disableClear'] = bool(struct.unpack_from('!B', data, offset[0])[0])
    offset[0] += 1
    result['ownerAlg'] = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    result['endorsementAlg'] = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    result['lockoutAlg'] = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    result['ownerPolicy'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['endorsementPolicy'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['lockoutPolicy'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['ownerAuth'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['endorsementAuth'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['lockoutAuth'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['EPSeed'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['SPSeed'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['PPSeed'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['phProof'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['shProof'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['ehProof'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['totalResetCount'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['resetCount'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    pcr_policy = libtpms_block_skip_read(data, offset, decode_libtpms_pcr_policies)
    if pcr_policy is not None:
        result['pcrPolicies'] = pcr_policy
    result['pcrAllocated'] = decode_libtpms_pcr_selection(data, offset)
    pplist = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    if hdr.version <= 4:
        result['ppListCompressed'] = pplist
    else:
        result['ppList'] = pplist
    result['failedTries'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['maxTries'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['recoveryTime'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['lockoutRecovery'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['lockOutAuthEnabled'] = bool(struct.unpack_from('!B', data, offset[0])[0])
    offset[0] += 1
    result['orderlyState'] = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    auditCommands = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    if hdr.version <= 4:
        result['auditCommandsCompressed'] = auditCommands
    else:
        result['auditCommands'] = auditCommands
    result['auditHashAlg'] = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 2
    result['auditCounter'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['algorithmSet'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['firmwareV1'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['firmwareV2'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    clocksize = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1 + clocksize
    result['timeEpoch'] = int.from_bytes(data[offset[0] - clocksize:offset[0]])
    if hdr.version >= 2:
        result.update(
            libtpms_block_skip_read(data, offset, decode_libtpms_persistent_data_v3) or {})
    return result


def decode_libtpms_drbg_state(data: bytes, offset: list[int]):
    result = {}
    hdr = LibtpmsHeader.decode(data, offset, 2, 0x6fe83ea1)
    result['reseedCounter'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['magic'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['seed'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    size = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 4 * size + 2
    result['lastValue'] = base64.b64encode(data[offset[0] - 4 * size:offset[0]]).decode()
    if hdr.version >= 2:
        libtpms_block_skip_read(data, offset, None)
    return result


def decode_libtpms_orderly_data_selfHealTimer(data: bytes):
    result = {}
    offset = [0]
    result['selfHealTimer'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['lockoutTimer'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['time'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    return result


def decode_libtpms_orderly_data(data: bytes, offset: list[int]):
    result = {}
    hdr = LibtpmsHeader.decode(data, offset, 2, 0x56657887)
    result['clock'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['clockSafe'] = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1
    result['drbgState'] = decode_libtpms_drbg_state(data, offset)
    result.update(
        libtpms_block_skip_read(data, offset, decode_libtpms_orderly_data_selfHealTimer) or {})
    if hdr.version >= 2:
        libtpms_block_skip_read(data, offset, None)
    return result


def decode_libtpms_state_reset_data_commitCounter(data: bytes):
    result = {}
    offset = [0]
    result['commitCounter'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['commitNonce'] = decode_libtpms_drbg_state(data, offset)
    result['commitArray'] = decode_libtpms_drbg_state(data, offset)
    return result


def decode_libtpms_state_reset_data_v3(data: bytes):
    result = {}
    offset = [0]
    result['nullSeedCompatLevel'] = struct.unpack_from('!B', data, offset[0])[0]
    offset[0] += 1
    libtpms_block_skip_read(data, offset, None)
    return result


def decode_libtpms_state_reset_data(data: bytes, offset: list[int]):
    result = {}
    hdr = LibtpmsHeader.decode(data, offset, 4, 0x01102332)
    result['nullProof'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['nullSeed'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['clearCount'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['objectContextID'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    size = struct.unpack_from('!H', data, offset[0])[0]
    offset[0] += 1
    contextArray = []
    if hdr.version <= 3:
        for i in range(size):
            contextArray.append(struct.unpack_from('!B', data, offset[0])[0])
            offset[0] += 1
        contextSlotMask = 0xff
    else:
        for i in range(size):
            contextArray.append(struct.unpack_from('!H', data, offset[0])[0])
            offset[0] += 2
        contextSlotMask = struct.unpack_from('!H', data, offset[0])[0]
        offset[0] += 2
    result['contextArray'] = contextArray
    result['contextSlotMask'] = contextSlotMask
    result['contextCounter'] = struct.unpack_from('!Q', data, offset[0])[0]
    offset[0] += 8
    result['commandAuditDigest'] = base64.b64encode(decode_libtpms_string(data, offset)).decode()
    result['restartCount'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result['pcrCounter'] = struct.unpack_from('!L', data, offset[0])[0]
    offset[0] += 4
    result.update(
        libtpms_block_skip_read(data, offset, decode_libtpms_state_reset_data_commitCounter) or {})
    if hdr.version >= 2:
        result.update(
            libtpms_block_skip_read(data, offset, decode_libtpms_state_reset_data_v3) or {})
    return result


def decode_libtpms_persistent_all(data: bytes):
    result = {}
    offset = [0]
    hdr = LibtpmsHeader.decode(data, offset, 4, 0xab364723)
    if hdr.version >= 4:
        result['profile'] = json.loads(decode_libtpms_string(data, offset))
    decode_libtpms_compile_constants(data, offset)
    result['persistent_data'] = decode_libtpms_persistent_data(data, offset)
    result['orderly_data'] = decode_libtpms_orderly_data(data, offset)
    if hdr.version < 3 or result['persistent_data']['orderlyState'] % 16384 == 1:
        result['state_reset_data'] = decode_libtpms_state_reset_data(data, offset)
    # TODO STATE_CLEAR_DATA
    # TODO INDEX_ORDERLY_RAM
    # TODO USER_NVRAM
    # TODO skip future versions
    return result


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
