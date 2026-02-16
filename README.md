# x3dh-ratchet

Crypto primitives based on the [Signal Protocol](https://signal.org/docs/) for secure asynchronous messaging with forward secrecy and cryptographic deniability.

This repository provides a strictly limited subset of the protocol suite:

- [**X3DH**](https://signal.org/docs/specifications/x3dh/) (Extended Triple Diffie-Hellman)

  Asynchronous key agreement protocol to establish a shared secret key between two parties who mutually authenticate each other based on public keys.

- [**Double Ratchet**](https://signal.org/docs/specifications/doubleratchet/)

  Used by two parties to exchange encrypted messages based on a shared secret key.

- [**XEdDSA**](https://signal.org/docs/specifications/xeddsa/)

  Enables use of a single key pair format for both elliptic curve Diffie-Hellman and signatures.

  Note that [**VXEdDSA**](https://signal.org/docs/specifications/xeddsa/#vxeddsa), an extension of **XEdDSA** to make it _verifiable random function_ (VRF), is currently not implemented. It may be added in the future.

## Disclaimer

This library is experimental and has not been externally audited.

Use at your own risk. The authors provide **no warranties** regarding security, functionality, or suitability for any purpose and **assume no liability** for any damages, data loss, or breaches resulting from its use.

## License

Distributed under the terms of the [BSD 3-Clause "New" or "Revised" License](./LICENSE). See LICENSE for further details.

## Legal & Cryptography Notice

This software implements cryptographic algorithms for secure messaging. The import, possession, use, and/or export of cryptographic software may be restricted in certain countries, including the United States, European Union member states, and other jurisdictions. Before using or distributing this software, you should check the applicable laws, regulations, and policies in your country.  
For general international guidance on cryptography controls, see the [Wassenaar Arrangement](http://www.wassenaar.org/).

**U.S. Users**. This software is classified under Export Control Commodity Classification Number (ECCN) 5D002.C.1, which includes information security software using asymmetric cryptography. Distribution in the United States and abroad may qualify for License Exception TSU (Technology Software Unrestricted) under the U.S. Export Administration Regulations (EAR), Section 740.13, for both source code and compiled code.

**EU Users**. Cryptography is subject to EU export control regulations and national laws in member states. Certain strong encryption software may require registration, licensing, or other compliance steps before distribution. Users are responsible for verifying local restrictions.

## Specification References

**Signal Protocol**          : <https://signal.org/docs/>

**X3DH**                     : <https://signal.org/docs/specifications/x3dh/>

**Double Ratchet**           : <https://signal.org/docs/specifications/doubleratchet/>

**XEdDSA**                   : <https://signal.org/docs/specifications/xeddsa/>
