import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(enhashTests.allTests),
        testCase(enscryptTests.allTests),
        testCase(scryptHelperTests.allTests),
        testCase(scryptTests.allTests),
    ]
}
#endif
