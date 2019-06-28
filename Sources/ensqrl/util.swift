import Foundation

// MARK: - Rotation

infix operator <<<
/// Constant-time left rotation.
/// - Parameter num: Unsigned integer to left-rotate.
/// - Parameter shift: Number of times to shift.
/// - Returns: Rotated value.
func <<< (num: UInt32, shift: UInt) -> UInt32 {
    return (num << shift) | (num >> ((~shift + 1) & 31))
}

// MARK: - XOR memory block

func blockXor(_ this: UnsafeMutableRawPointer,
              with that: UnsafeRawPointer,
              forByteCount l: Int) {
    let x = this.assumingMemoryBound(to: UInt64.self)
    let y = that.assumingMemoryBound(to: UInt64.self)
    let count = l / MemoryLayout<UInt64>.stride
    
    for i in 0 ..< count {
        x[i] ^= y[i]
    }
}

// MARK: - Data to Array

extension Data {
    /// Create an array of unsigned integers of type `T` from `Data`
    /// - Parameter type: Type of unsigned integer
    /// - Returns: Array of unsigned integers of type `T`
    func toArray<T: BinaryInteger>(type: T.Type) -> [T] {
        var array = Array<T>(repeating: 0, count: count/MemoryLayout<T>.stride)
        _ = array.withUnsafeMutableBytes { copyBytes(to: $0) }
        return array
    }
}
