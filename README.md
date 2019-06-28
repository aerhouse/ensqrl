# ensqrl

Swift-native implementations of [SQRL](https://www.grc.com/sqrl/sqrl.htm)'s enhash and enscrypt functions using Apple's crypto frameworks.

Note: The `enhash` test requires macOS 10.15 or an iOS 13 simulator to run. To run the remaining tests on an earlier OS, comment out the `enhash` function in `enhash.swift` and the `enhashTests` class in `ensqrlTests.swift`.

**Warning**: Until macOS 10.15 is stable enough to work on, `enscrypt` uses insecure strings to represent the password for testing purposes. This will be replaced with the CryptoKit-provided `SymmetricKey` struct, and the salt's `Data` type will be replaced with `AES.GCM.Nonce`. 

Pointer arithmetic in the scrypt implementation courtesy of [Marcin Krzyżanowski](http://krzyzanowskim.com/).
