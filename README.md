# ensqrl

Swift-native implementations of [SQRL](https://www.grc.com/sqrl/sqrl.htm)'s enhash and enscrypt functions using Apple's crypto frameworks.

Note: Because CryptoKit is only on macOS 10.15 and iOS 13, `enhash` is set to run on a simulator for testing.

**Warning**: Until macOS 10.15 is stable enough to work on, `enscrypt` uses insecure strings to represent the password for testing purposes. This will be replaced with the CryptoKit-provided `SymmetricKey` struct, and the salt's `Data` type will be replaced with `AES.GCM.Nonce`. 

Pointer arithmetic in the scrypt implementation courtesy of [Marcin Krzyżanowski](http://krzyzanowskim.com/).
