# x3dh-ratchet

Cryptographic primitives based on the [Signal Protocol](https://signal.org/docs/) for secure asynchronous messaging with forward secrecy and cryptographic deniability.

This repository implements a strictly limited subset of the protocol suite:

- [**X3DH**](https://signal.org/docs/specifications/x3dh/) (Extended Triple Diffie-Hellman)

  Asynchronous key agreement protocol to establish a shared secret key between two parties who mutually authenticate each other based on public keys.

- [**Double Ratchet**](https://signal.org/docs/specifications/doubleratchet/)

  Used by two parties to exchange encrypted messages based on a shared secret key.

- [**XEdDSA**](https://signal.org/docs/specifications/xeddsa/)

  Enables use of a single key pair format for both elliptic curve Diffie-Hellman and signatures.

  Note that [**VXEdDSA**](https://signal.org/docs/specifications/xeddsa/#vxeddsa), an extension of **XEdDSA** to make it _verifiable random function_ (VRF), is currently not implemented. It may be added in the future.

## Status

This library is still experimental. Although it has been extensively tested, it has not been externally audited. Use at your own risk.

## License

See [LICENSE](./LICENSE) file.

## Specification References

**Signal Protocol Overview**

<https://signal.org/docs/>

**X3DH**

<https://signal.org/docs/specifications/x3dh/>

**Double Ratchet**

<https://signal.org/docs/specifications/doubleratchet/>

**XEdDSA**

<https://signal.org/docs/specifications/xeddsa/>
