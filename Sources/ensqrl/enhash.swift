import Foundation
import CryptoKit

/// Iteratively hash a value 16 times with SHA-256 and XOR each intermediate digest together.
/// - Parameter input: Byte buffer to be hashed.
/// - Returns: A 32-byte buffer of the XOR'd digests.
@available(OSX 10.15, iOS 13, *)
public func enhash<D: DataProtocol>(_ input: D) -> Data {
    func xor(_ this: UnsafeMutableBufferPointer<UInt64>,
             with that: UnsafeMutableBufferPointer<UInt64>) {
        for i in 0 ..< 4 {
            this[i] ^= that[i]
        }
    }

    // Pointer to XOR-output buffer
    let tmp = UnsafeMutableBufferPointer<UInt64>.allocate(capacity: 4)
    tmp.initialize(repeating: 0)

    // Pointer to hash-output buffer
    let hashBuf = UnsafeMutableBufferPointer<UInt64>.allocate(capacity: 4)
    hashBuf.initialize(repeating: 0)
    let hashPtr = UnsafeRawBufferPointer.init(hashBuf)

    // Cleanup
    defer {
        tmp.assign(repeating: 0)
        tmp.deallocate()
        hashBuf.assign(repeating: 0)
        hashBuf.deallocate()
    }

    // tmp <- tmp (+) HASH(hashBuf)
    // First iteration
    _ = SHA256.hash(data: input).withUnsafeBytes {
        $0.copyBytes(to: hashBuf)
    }
    xor(tmp, with: hashBuf)

    // Second through sixteenth iterations
    for _ in 2 ... 16 {
        _ = SHA256.hash(bufferPointer: hashPtr).withUnsafeBytes {
            $0.copyBytes(to: hashBuf)
        }
        xor(tmp, with: hashBuf)
    }

    return Data.init(buffer: tmp)
}
