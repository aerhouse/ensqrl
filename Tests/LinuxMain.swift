import XCTest

import ensqrlTests

var tests = [XCTestCaseEntry]()
tests += enhashTests.allTests()
tests += enscryptTests.allTests()
tests += scryptHelperTests.allTests()
tests += scryptTests.allTests()
XCTMain(tests)
