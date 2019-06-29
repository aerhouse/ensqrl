import Foundation
import CommonCrypto

/// Scrypt PBKDF
/// - Parameter pw: Pointer to password
/// - Parameter pwLen: Password length
/// - Parameter salt: Pointer to salt
/// - Parameter sLen: Salt length
/// - Parameter N: CPU/Memory cost factor
/// - Parameter r: Block size
/// - Parameter p: Parallelization factor
/// - Parameter derivedKeyDestination: Pointer to place derived key
/// - Parameter dkLen: Length of derived key
/// - Parameter mixedSalt: Buffer for the derived salt
/// - Parameter romixTmp: Buffer for ROMix function
/// - Parameter V: Buffer for ROMix mixing array
///
/// An implementation of [scrypt](https://tools.ietf.org/html/rfc7914) specialized
/// for iterative execution. In particular, the memory used in the derivation is allocated before
/// calling and is subject to the following:
/// - Requires: `|mixedSalt| == 128 * r * p` bytes
/// - Requires: `|romixTmp| == 256 * r + 128` bytes
/// - Requires: `|V| == 128 * N * r` bytes
///
/// ---
/// The parameters are subject to the following requirements, per the RFC:
///
/// - Requires: `N > 1 && N < 2^(16 * r)`
/// - Requires: `p > 0 && p <= (2^32 - 1) / (4 * r)`
/// - Requires: `dkLen > 0 && dkLen <= (2^32 - 1) * 32`
///
/// - Warning: These requirements are not checked in the code to prevent needlessly repeated calculation.
/// ---
func scrypt(password pw: UnsafePointer<Int8>,
            passwordLength pwLen: Int,
            salt: UnsafePointer<UInt8>,
            saltLength sLen: Int,
            cost N: Int,
            blockSize r: Int,
            parallelization p: Int,
            derivedKeyDestination dk: UnsafeMutablePointer<UInt8>,
            derivedKeyLength dkLen: Int,
            withMemory mixedSalt: UnsafeMutablePointer<UInt8>,
            _ romixTmp: UnsafeMutablePointer<UInt32>,
            _ V: UnsafeMutablePointer<UInt32>
    ) {
    
    // Expand the password using PBKDF2-HMAC-SHA256 to create salt for the
    // second application of the same function.
    var status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCHmacAlgSHA256), pw, pwLen, salt, sLen, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1, mixedSalt, 128 * p * r)
    
    if status != Int32(kCCSuccess) {
        fatalError("CCKeyDerivationPBKDF failed: \(status)")
    }
    
    // Mix the new salt
    for i in 0 ..< p {
        roMix(input: mixedSalt + i * 128 * r,
              romixArray: V,
              tmpMemory: romixTmp,
              cost: N,
              blockSize: r)
    }
    
    // Set status to prevent misreported success of second PBKDF.
    status = Int32.max
    
    // Expand the password using the mixed salt.
    status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCHmacAlgSHA256), pw, pwLen, mixedSalt, 128 * p * r, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1, dk, dkLen)

    if status != Int32(kCCSuccess) {
        fatalError("CCKeyDerivationPBKDF failed: \(status)")
    }
}

// MARK: - ROMix

func roMix(input: UnsafeMutableRawPointer,
           romixArray: UnsafeMutablePointer<UInt32>,
           tmpMemory: UnsafeMutablePointer<UInt32>,
           cost N: Int,
           blockSize r: Int
    ) {
    func integerify(_ i: UnsafeRawPointer) -> UInt64 {
        return (i + (2 * r - 1) * 64).load(as: UInt64.self).littleEndian
    }
    
    // Evenly divide temporary memory for blockMix
    let X = tmpMemory
    let Y = tmpMemory + 32 * r
    let bmTmp = tmpMemory + 64 * r
    
    // X <- input
    X.assign(from: input.assumingMemoryBound(to: UInt32.self), count: 32 * r)
    
    for i in stride(from: 0, to: N, by: 2) {
        // V[i] <- X
        UnsafeMutableRawPointer(romixArray + 32 * i * r).copyMemory(from: X, byteCount: 128 * r)
        
        // Mix
        blockMix(input: X, output: Y, tmpBlock: bmTmp, blockSize: r)
        
        // V[i + 1] <- Y
        UnsafeMutableRawPointer(romixArray + 32 * (i + 1) * r).copyMemory(from: Y, byteCount: 128 * r)
        
        // Mix
        blockMix(input: Y, output: X, tmpBlock: bmTmp, blockSize: r)
    }
    
    var j: Int
    for _ in stride(from: 0, to: N, by: 2) {
        // j <- integerify(X) mod N
        j = Int(integerify(X) & UInt64(N - 1))
        
        // X <- X (+) romixArray[j]
        blockXor(X, with: romixArray + 32 * j * r, forByteCount: 128 * r)
        // Y <- blockMix(X)
        blockMix(input: X, output: Y, tmpBlock: bmTmp, blockSize: r)
        
        // j <- integerify(Y) mod N
        j = Int(integerify(Y) & UInt64(N - 1))
        
        // Y <- Y (+) romixArray[j]
        blockXor(Y, with: romixArray + 32 * j * r, forByteCount: 128 * r)
        // X <- blockMix(Y)
        blockMix(input: Y, output: X, tmpBlock: bmTmp, blockSize: r)
    }
    
    // input <- X
    for i in 0 ..< 32 * r {
        UnsafeMutableRawPointer(input + 4 * i).storeBytes(of: X[i], as: UInt32.self)
    }
}

// MARK: - Block Mix

func blockMix(input: UnsafePointer<UInt32>,
              output: UnsafeMutablePointer<UInt32>,
              tmpBlock tmp: UnsafeMutablePointer<UInt32>,
              blockSize r: Int
    ) {
    let salsaTmp = UnsafeMutablePointer(tmp + 16)
    // tmp <- input[2*r - 1]
    UnsafeMutableRawPointer(tmp).copyMemory(from: input + (2 * r - 1) * 16, byteCount: 64)
    
    for i in stride(from: 0, to: 2 * r, by: 2) {
        // tmp <- tmp (+) input[i]
        blockXor(tmp, with: input + 16 * i, forByteCount: 64)
        // Mix
        salsa_20_8(tmp, tmpBlock: salsaTmp)
        
        // Even output indices
        // output[i] <- tmp
        UnsafeMutableRawPointer(output + 8 * i).copyMemory(from: tmp, byteCount: 64)
        
        // tmp <- tmp (+) input[i + 1]
        blockXor(tmp, with: input + 16 * i + 16, forByteCount: 64)
        // Mix
        salsa_20_8(tmp, tmpBlock: salsaTmp)
        
        // Odd output indices
        // output[i + 1] <- tmp
        UnsafeMutableRawPointer(output + 8 * i + 16 * r).copyMemory(from: tmp, byteCount: 64)
    }
}

// MARK: - Salsa20/8 Core Function

func salsa_20_8(_ input: UnsafeMutablePointer<UInt32>, tmpBlock x: UnsafeMutablePointer<UInt32>) {
    x.assign(from: input, count: 16)
    
    for _ in stride(from: 0, to: 8, by: 2) {
        x[ 4] ^= ( x[ 0] &+ x[12] ) <<<  7; x[ 8] ^= ( x[ 4] &+ x[ 0] ) <<<  9
        x[12] ^= ( x[ 8] &+ x[ 4] ) <<< 13; x[ 0] ^= ( x[12] &+ x[ 8] ) <<< 18
        x[ 9] ^= ( x[ 5] &+ x[ 1] ) <<<  7; x[13] ^= ( x[ 9] &+ x[ 5] ) <<<  9
        x[ 1] ^= ( x[13] &+ x[ 9] ) <<< 13; x[ 5] ^= ( x[ 1] &+ x[13] ) <<< 18
        x[14] ^= ( x[10] &+ x[ 6] ) <<<  7; x[ 2] ^= ( x[14] &+ x[10] ) <<<  9
        x[ 6] ^= ( x[ 2] &+ x[14] ) <<< 13; x[10] ^= ( x[ 6] &+ x[ 2] ) <<< 18
        x[ 3] ^= ( x[15] &+ x[11] ) <<<  7; x[ 7] ^= ( x[ 3] &+ x[15] ) <<<  9
        x[11] ^= ( x[ 7] &+ x[ 3] ) <<< 13; x[15] ^= ( x[11] &+ x[ 7] ) <<< 18
        x[ 1] ^= ( x[ 0] &+ x[ 3] ) <<<  7; x[ 2] ^= ( x[ 1] &+ x[ 0] ) <<<  9
        x[ 3] ^= ( x[ 2] &+ x[ 1] ) <<< 13; x[ 0] ^= ( x[ 3] &+ x[ 2] ) <<< 18
        x[ 6] ^= ( x[ 5] &+ x[ 4] ) <<<  7; x[ 7] ^= ( x[ 6] &+ x[ 5] ) <<<  9
        x[ 4] ^= ( x[ 7] &+ x[ 6] ) <<< 13; x[ 5] ^= ( x[ 4] &+ x[ 7] ) <<< 18
        x[11] ^= ( x[10] &+ x[ 9] ) <<<  7; x[ 8] ^= ( x[11] &+ x[10] ) <<<  9
        x[ 9] ^= ( x[ 8] &+ x[11] ) <<< 13; x[10] ^= ( x[ 9] &+ x[ 8] ) <<< 18
        x[12] ^= ( x[15] &+ x[14] ) <<<  7; x[13] ^= ( x[12] &+ x[15] ) <<<  9
        x[14] ^= ( x[13] &+ x[12] ) <<< 13; x[15] ^= ( x[14] &+ x[13] ) <<< 18
    }
    
    for i in 0 ..< 16 {
        input[i] &+= x[i]
    }
}
