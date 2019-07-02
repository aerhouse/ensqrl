import Foundation

public enum EnscryptMode {
    case iteration
    case duration
}

/// Iteratively execute scrypt and XOR each intermediately produced key together.
/// - Parameter password: User-provided password.
/// - Parameter salt: _Optional_. 32-byte pseudo-random salt.
/// - Parameter N: CPU/Memory cost for scrypt.
/// - Parameter mode: `.iteration` or `.duration`
/// - Parameter count: Number of iterations or number of seconds to iterate.
///
/// - Returns: Named tuple containing the number of iterations (`iterations`) and the resultant 32-byte key (`key`).
public func enscrypt(password: String, salt: Data?, cost N: Int, mode: EnscryptMode, count: Int) -> (iterations: Int, key: Data) {
    // Constant scrypt parameters
    let r = 256
    let p = 1
    let dkLen = 32
    
    guard salt?.count == dkLen || salt == nil else { fatalError("Invalid salt size") }
    
    func xor(_ this: inout [UInt8],
             with that: [UInt8]) {
        for i in 0 ..< dkLen {
            this[i] ^= that[i]
        }
    }
    
    // Allocate memory
    var pw = password.data(using: .utf8)!.toArray(type: Int8.self)
    var sBuf = salt == nil ? [UInt8](repeating: 0, count: dkLen) : salt!.toArray(type: UInt8.self)
    var saltTmp = [UInt8](repeating: 0, count: 32_768)
    var dk = [UInt8](repeating: 0, count: dkLen)
    var tmp = [UInt8](repeating: 0, count: dkLen)
    var romixTmp = [UInt32](repeating: 0, count: 16_416)
    var V = [UInt32](repeating: 0, count: 8_192 * N)
    
    // Cleanup memory
    // Dealloations are automatic since we're using arrays
    defer {
        saltTmp.resetBytes(in: saltTmp.startIndex...)
        dk.resetBytes(in: dk.startIndex...)
        tmp.resetBytes(in: tmp.startIndex...)
        sBuf.resetBytes(in: sBuf.startIndex...)
        for i in 0 ..< pw.count {
            pw[i] = 0
        }
        for i in 0 ..< romixTmp.count {
            romixTmp[i] = 0
        }
        for i in 0 ..< V.count {
            V[i] = 0
        }
    }
    
    switch mode {
    case .iteration:
        // Allow for no salt
        var sLen = salt == nil ? 0 : dkLen
        let iterations = max(count, 1)
        
        for _ in 0 ..< iterations {
            scrypt(password: &pw,
                   passwordLength: pw.count,
                   salt: &sBuf,
                   saltLength: sLen,
                   cost: N,
                   blockSize: r,
                   parallelization: p,
                   derivedKeyDestination: &dk,
                   derivedKeyLength: dkLen,
                   withMemory: &saltTmp,
                   &romixTmp,
                   &V)
            
            // tmp <- tmp (+) derived key
            xor(&tmp, with: dk)
            
            // Copy derived key to salt buffer
            for i in 0 ..< dkLen {
                sBuf[i] = dk[i]
            }
            
            // Ensure intermediate salts are 32 bytes
            sLen = dkLen
        }

        return (iterations, Data(tmp))
        
    case .duration:
        // Allow for no salt
        var sLen = salt == nil ? 0 : dkLen
        
        var iterations = 0
        let endTime = DispatchTime.now() + DispatchTimeInterval.seconds(count)
        
        repeat {
            iterations += 1
            
            scrypt(password: &pw,
                   passwordLength: pw.count,
                   salt: &sBuf,
                   saltLength: sLen,
                   cost: N,
                   blockSize: r,
                   parallelization: p,
                   derivedKeyDestination: &dk,
                   derivedKeyLength: dkLen,
                   withMemory: &saltTmp,
                   &romixTmp,
                   &V)
            
            // tmp <- tmp (+) derived key
            xor(&tmp, with: dk)
            
            // Copy derived key to salt buffer
            for i in 0 ..< dkLen {
                sBuf[i] = dk[i]
            }
            
            // Ensure intermediate salts are 32 bytes
            sLen = dkLen
        } while DispatchTime.now() < endTime
        
        return (iterations, Data(tmp))
    }
}
