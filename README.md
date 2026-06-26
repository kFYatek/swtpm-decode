# swtpm_decode

This is a quick and dirty script that intends to show contents of persistence
data used by [swtpm](https://github.com/stefanberger/swtpm) and
[libtpms](https://github.com/stefanberger/libtpms), which is commonly used to
emulate the Trusted Platform Module on virtual machines that use the QEMU engine
(including KVM, libvirt, UTM, etc.) as well as VirtualBox.

The tool dynamically searches for libtpms persistence magic, so it should work
with any format that embeds this information without encryption, including
linear `swtpm` files (e.g. `tpmdata` used by UTM), `tpm2-00.permall` files found
in`swtpm` directories (used by e.g. libvirt) and `*.nvram` files used by
VirtualBox.

Currently, it only supports a subset of the format that was enough to decode
data encounter on a couple of test virtual machines running Windows 11 and
Ubuntu 26.04 under QEMU 10.x and VirtualBox 7.2, using libtpms 0.9.0 through
0.10.2.

It is intended for educational purposes, to learn about the internals and inner
workings of the TPM.

## Relevant links

More resources about the TPM:

* https://blog.scrt.ch/2023/09/15/a-deep-dive-into-tpm-based-bitlocker-drive-encryption/
* https://wiki.archlinux.org/title/Trusted_Platform_Module

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
