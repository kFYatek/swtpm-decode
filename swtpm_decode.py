#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import sys


def decode_data(data: bytes):
    raise Exception('Not yet implemented')


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
