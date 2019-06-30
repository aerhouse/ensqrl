import XCTest
@testable import ensqrl

#if targetEnvironment(simulator)
@available(OSX 10.15, iOS 13, *)
final class enhashTests: XCTestCase {
    func testEnhash() {
        let input1 = Data.init(fromHex: """
00010203040506070809000102030405
06070809000102030405060708090001
""")!
        let expected1 = Data.init(fromHex: """
5827fa4d2b417638b4e4612bcbc339ea
89754e640020012d8fe5bbed7ca1d15f
""")!

        XCTAssertEqual(enhash(input1), expected1)

        let input2 = Data.init(fromHex: """
00010203040506070809000102030405
06070809000102030405060708090001
""")!
        let expected2 = Data.init(fromHex: """
5827fa4d2b417638b4e4612bcbc339ea
89754e640020012d8fe5bbed7ca1d15f
""")!

       XCTAssertEqual(enhash(input2), expected2)
    }

    static var allTests = [
        ("testEnhash", testEnhash),
    ]
}
#endif

final class scryptTests: XCTestCase {
    func testScrypt1() {
        let expected = Data.init(fromHex: """
77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
""")!.toArray(type: UInt8.self)
        
        var pw = "".data(using: .utf8)!.toArray(type: Int8.self)
        var salt = "".data(using: .utf8)!.toArray(type: UInt8.self)
        let N = 16
        let r = 1
        let p = 1
        let dkLen = 64
        
        var newSalt = [UInt8](repeating: 0, count: 128 * r * p)
        var romixTmp = [UInt32](repeating: 0, count: (256 * r + 128) / 4)
        var V = [UInt32](repeating: 0, count: (128 * N * r) / 4)
        var dk = [UInt8](repeating: 0, count: dkLen)
        
        scrypt(password: &pw, passwordLength: pw.count, salt: &salt, saltLength: salt.count, cost: N, blockSize: r, parallelization: p, derivedKeyDestination: &dk, derivedKeyLength: dkLen, withMemory: &newSalt, &romixTmp, &V)
        XCTAssertEqual(expected, dk)
    }
    
    func testScrypt2() {
        let expected = Data.init(fromHex: """
fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
""")!.toArray(type: UInt8.self)
        
        var pw = "password".data(using: .utf8)!.toArray(type: Int8.self)
        var salt = "NaCl".data(using: .utf8)!.toArray(type: UInt8.self)
        let N = 1024
        let r = 8
        let p = 16
        let dkLen = 64
        
        var newSalt = [UInt8](repeating: 0, count: 128 * r * p)
        var romixTmp = [UInt32](repeating: 0, count: (256 * r + 128) / 4)
        var V = [UInt32](repeating: 0, count: (128 * N * r) / 4)
        var dk = [UInt8](repeating: 0, count: dkLen)
        
        scrypt(password: &pw, passwordLength: pw.count, salt: &salt, saltLength: salt.count, cost: N, blockSize: r, parallelization: p, derivedKeyDestination: &dk, derivedKeyLength: dkLen, withMemory: &newSalt, &romixTmp, &V)
        XCTAssertEqual(expected, dk)
    }
    
    func testScrypt3() {
        let expected = Data.init(fromHex: """
70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
""")!.toArray(type: UInt8.self)
        
        var pw = "pleaseletmein".data(using: .utf8)!.toArray(type: Int8.self)
        var salt = "SodiumChloride".data(using: .utf8)!.toArray(type: UInt8.self)
        let N = 16384
        let r = 8
        let p = 1
        let dkLen = 64
        
        var newSalt = [UInt8](repeating: 0, count: 128 * r * p)
        var romixTmp = [UInt32](repeating: 0, count: (256 * r + 128) / 4)
        var V = [UInt32](repeating: 0, count: (128 * N * r) / 4)
        var dk = [UInt8](repeating: 0, count: dkLen)
        
        scrypt(password: &pw, passwordLength: pw.count, salt: &salt, saltLength: salt.count, cost: N, blockSize: r, parallelization: p, derivedKeyDestination: &dk, derivedKeyLength: dkLen, withMemory: &newSalt, &romixTmp, &V)
        XCTAssertEqual(expected, dk)
    }
    
    // Loooooong test
    //    func testScrypt4() {
    //        let expected = Data.init(fromHex: """
    //21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
    //ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
    //8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
    //37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
    //""")!.toArray(type: UInt8.self)
    //
    //        var pw = "pleaseletmein".data(using: .utf8)!.toArray(type: Int8.self)
    //        var salt = "SodiumChloride".data(using: .utf8)!.toArray(type: UInt8.self)
    //        let N = 1048576
    //        let r = 8
    //        let p = 1
    //        let dkLen = 64
    //
    //        var newSalt = [UInt8](repeating: 0, count: 128 * r * p)
    //        var romixTmp = [UInt32](repeating: 0, count: (256 * r + 64) / 4)
    //        var V = [UInt32](repeating: 0, count: (128 * N * r) / 4)
    //        var dk = [UInt8](repeating: 0, count: 64)
    //
    //        scrypt(password: &pw, passwordLength: pw.count, salt: &salt, saltLength: salt.count, cost: N, blockSize: r, parallelization: p, derivedKeyDestination: &dk, derivedKeyLength: dkLen, withMemory: &newSalt, &romixTmp, &V)
    //        XCTAssertEqual(expected, dk)
    //    }
    
    static var allTests = [
        ("testScrypt1", testScrypt1),
        ("testScrypt2", testScrypt2),
        ("testScrypt3", testScrypt3),
//        ("testScrypt4", testScrypt4),
    ]
}

final class scryptHelperTests: XCTestCase {
    func testSalsa() {
        var input = Data.init(fromHex: """
7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26
ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d
ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32
76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e
""")!.toArray(type: UInt32.self)
        let expected = Data.init(fromHex: """
a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81
""")!.toArray(type: UInt32.self)
        
        var tmp = [UInt32](repeating: 0, count: 16)
        
        salsa_20_8(&input, tmpBlock: &tmp)
        XCTAssertEqual(input, expected)
    }
    
    func testBlockMix() {
        var input = Data.init(fromHex: """
f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
""")!.toArray(type: UInt32.self)
        input.append(contentsOf:
            Data.init(fromHex: """
89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
""")!.toArray(type: UInt32.self))
        
        var expected = Data.init(fromHex: """
a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81
""")!.toArray(type: UInt32.self)
        expected.append(contentsOf:
            Data.init(fromHex: """
20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c
21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7
7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6
5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25
""")!.toArray(type: UInt32.self))
        
        var output = [UInt32](repeating: 0, count: 32)
        var tmp = [UInt32](repeating: 0, count: 128 / 4)
        
        blockMix(input: &input, output: &output, tmpBlock: &tmp, blockSize: 1)
        XCTAssertEqual(output, expected)
    }
    
    func testROMix() {
        var input = Data.init(fromHex: """
f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
""")!.toArray(type: UInt8.self)
        
        let expected = Data.init(fromHex: """
79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6
2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46
d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26
a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71
ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c
ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4
ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f
4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e
""")!.toArray(type: UInt8.self)
        
        let r = 1
        let N = 16
        
        var V = [UInt32](repeating: 0, count: (128 * r * N) / 4)
        var XY = [UInt32](repeating: 0, count: (256 * r + 128) / 4)
        
        roMix(input: &input, romixArray: &V, tmpMemory: &XY, cost: N, blockSize: r)
        XCTAssertEqual(input, expected)
    }
    
    static var allTests = [
        ("testSalsa", testSalsa),
        ("testBlockMix", testBlockMix),
        ("testROMix", testROMix),
    ]
}

final class enscryptTests: XCTestCase {
    func testIterEnscrypt1() {
        let expected = Data.init(fromHex: "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c")!
        
        let pw = ""
        let iterations = 1
        
        XCTAssertEqual(expected, enscrypt(password: pw, salt: nil, cost: 512, mode: .iteration, count: iterations).key)
    }
    
    func testIterEnscrypt2() {
        let expected = Data.init(fromHex: "a6e74d1f707cdc909f99826eb6c562694d91fc12d31a552b17f88ca153a1b497")!
        
        let pw = ""
        let iterations = 5
        
        XCTAssertEqual(expected, enscrypt(password: pw, salt: nil, cost: 512, mode: .iteration, count: iterations).key)
    }
    
    func testIterEnscrypt3() {
        let expected = Data.init(fromHex: "6931d8e0ec5102bc0e0c9d5b8a8a7184b6478c6125c92d440428e6835bf43e0b")!
        
        let pw = "password"
        let iterations = 5
        
        XCTAssertEqual(expected, enscrypt(password: pw, salt: nil, cost: 512, mode: .iteration, count: iterations).key)
    }
    
    func testIterEnscrypt4() {
        let expected = Data.init(fromHex: "02a44f8ce147bfe588180b0b4e5e5f13190ac0125d4565229d5cd838428e9841")!
        
        let pw = "password"
        let salt = Data.init(count: 32)
        let iterations = 5
        
        XCTAssertEqual(expected, enscrypt(password: pw, salt: salt, cost: 512, mode: .iteration, count: iterations).key)
    }
    
    func testDurationEnscrypt() {
        let pw = ""
        let salt: Data? = nil
        let duration = 3
        
        self.measure {
            let (_,_) = enscrypt(password: pw, salt: salt, cost: 2, mode: .duration, count: duration)
        }
    }
    
    // Long tests on my poor little laptop
//    func testIterEnscrypt5() {
//        let expected = Data.init(fromHex: "45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67")!
//
//        let pw = ""
//        let salt = "".data(using: .utf8)!
//        let iterations = 100
//
//        XCTAssertEqual(expected, iterativeEnscrypt(password: pw, salt: salt, cost: 1, iterations: iterations))
//    }
//
//    func testIterEnscrypt6() {
//        let expected = Data.init(fromHex: "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d")!
//
//        let pw = "password"
//        let salt = Data.init(count: 32)
//        let iterations = 123
//
//        XCTAssertEqual(expected, iterativeEnscrypt(password: pw, salt: salt, cost: 1, iterations: iterations))
//    }
    
    static var allTests = [
        ("testIterEnscrypt1", testIterEnscrypt1),
        ("testIterEnscrypt2", testIterEnscrypt2),
        ("testIterEnscrypt3", testIterEnscrypt3),
        ("testIterEnscrypt4", testIterEnscrypt4),
        ("testDurationEnscrypt", testDurationEnscrypt),
//        ("testIterEnscrypt5", testIterEnscrypt5),
//        ("testIterEnscrypt6", testIterEnscrypt6),
    ]
}

fileprivate extension Data {
    init?(fromHex hexString: String) {
        let str = hexString.filter { !$0.isWhitespace }
        guard str.count % 2 == 0 && str.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }
        
        let bytes: [UInt8] = stride(from: 0, to: str.count, by: 2)
            .map {
                let idx = str.index(str.startIndex, offsetBy: $0)
                
                return UInt8(str[idx...str.index(after: idx)], radix: 16)!
        }
        
        self = Data(bytes)
    }
}
