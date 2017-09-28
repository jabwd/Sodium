//
//  SodiumTests.swift
//  SodiumTests
//
//  Created by Antwan van Houdt on 28/09/2017.
//

import XCTest
import Sodium

class SodiumTests: XCTestCase {
	
	let password = "Correct Horse Battery Staple!"
	
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
	
	func testPasswordHash() {
		guard let hash = Hash.createPasswordHash(password) else {
			XCTAssert(false)
			return
		}
		print("Password hash: \(hash)")
		
		XCTAssert(Hash.verifyPassword(password, hash: hash))
	}
	
	func testPasswordPerformance() {
		var hash: String = ""
		self.measure {
			hash = Hash.createPasswordHash(password) ?? ""
			let _ = Hash.verifyPassword(password, hash: hash)
		}
	}
    
    func testBlake2Hash() {
		let key  = Data.random(Hash.keySize)
		let key2 = Data.random(Hash.keySize)
		
		XCTAssert(key != key2)
		
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
	
	func testSecretBox() {
		let box = SecretBox()
		
		let message = "heontsuhoanshuaenohuesnoahueaons"
		
		let cipher = box.encrypt(message)
		
		let decrypted = box.decrypt(cipher) ?? ""
		XCTAssert(decrypted == message)
	}
    
}
