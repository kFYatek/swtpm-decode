# swtpm_decode

This is a quick and dirty script that intends to show contents of persistence
files used by [swtpm](https://github.com/stefanberger/swtpm), which is commonly
used to emulate the Trusted Platform Module on virtual machines that use the
QEMU engine (including KVM, libvirt, UTM, etc.).

Currently, it only supports a subset of the format that was enough to decode the
file created by performing a clean installation of Windows 11 ARM64 with default
settings of BitLocker and a Windows Hello PIN, running under
[UTM](https://github.com/utmapp/UTM/) 4.7.5 (QEMU 10.0.2 and swtpm 0.9.0).

It is intended for educational purposes, to learn about the internals and inner
workings of the TPM.

## Legal disclaimers

I, the author, don't care about what you do with this code. As far as I'm
concerned, you're free to use it however you like, with or without attribution.
Treat it as [public domain](https://en.wikipedia.org/wiki/Public_domain),
[CC0](https://creativecommons.org/publicdomain/zero/1.0/) or
[WTFPL](https://www.wtfpl.net/about/), whatever is the most convenient or
legally appropriate for you.

It was created by reverse engineering the code from
[swtpm](https://github.com/stefanberger/swtpm) and
[libtpms](https://github.com/stefanberger/libtpms). It may mean that this
project shall be considered a derivative work of those. Licenses and copyright
notices of the aforementioned projects are reproduced here as an effort to
comply with their BSD-style licenses: [LICENSE.libtpms](./LICENSE.libtpms),
[LICENSE.swtpm](./LICENSE.swtpm). I am not a lawyer, please consult one if in
doubt of how those are applicable to this project.
