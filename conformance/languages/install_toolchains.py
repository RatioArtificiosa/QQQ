#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install the exact Linux x86_64 compiler archives used by the language probes.

Requires Python 3.12+. Refuses an existing prefix. Node, Go, Python and Rust are
installed separately by CI. Archive hashes are publisher release SHA-256 digests.
"""
import argparse
import hashlib
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

ASSETS = {
    'tinygo': ('https://github.com/tinygo-org/tinygo/releases/download/v0.42.0/tinygo0.42.0.linux-amd64.tar.gz',
               'b87688fa2e19cee7d813cad7fd7dadb71dff3198e47125aba66ba4af5e490438'),
    'binaryen': ('https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-linux.tar.gz',
                 '2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489'),
    'wasi-sdk': ('https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz',
                 'b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4'),
    'wit-bindgen': ('https://github.com/bytecodealliance/wit-bindgen/releases/download/v0.62.0/wit-bindgen-0.62.0-x86_64-linux.tar.gz',
                    '3e81cc6523729f7532b4aa7968648a04abf0c711b7d1677150e9121f4e6458fe'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        parser.error('these pinned archives are Linux x86_64 only; use documented native toolchains elsewhere')
    args.prefix.mkdir(parents=True, exist_ok=False)
    for name, (url, digest) in ASSETS.items():
        with tempfile.TemporaryFile() as archive:
            sha = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=90) as response:
                while block := response.read(1024 * 1024):
                    sha.update(block)
                    archive.write(block)
            if sha.hexdigest() != digest:
                raise ValueError(f'{name}: archive digest mismatch; nothing extracted')
            archive.seek(0)
            with tarfile.open(fileobj=archive, mode='r:gz') as tar:
                tar.extractall(args.prefix / name, filter='data')
        print(f'{name}: verified {digest}')


if __name__ == '__main__':
    main()
