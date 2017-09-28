//
//  SodiumTests.swift
//  SodiumTests
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import XCTest
import Sodium

class SodiumTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testBlake2Hash() {
		let key  = Data.random(Hash.keySize)
		let key2 = Data.random(Hash.keySize)
		
		let hash  = Hash.blake(key2, key: key)
		let hash2 = Hash.blake(key2, key: key)
		let hash3 = Hash.blake(key, key: key2)
		
		XCTAssert(hash == hash2)
		XCTAssert(hash3 != hash2)
    }
    
    func testRandomBytesPerformance() {
        self.measure {
			for _ in 0..<1000 {
				let _ = Data.random(Hash.keySize)
			}
        }
    }
    
}
