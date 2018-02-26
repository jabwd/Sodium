//
//  SodiumTests2.swift
//  SodiumTests2
//
//  Created by Antwan van Houdt on 26/02/2018.
//

import XCTest
import Sodium

class SodiumTests2: XCTestCase {
	
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
		
		let message = "Hello World!"
		
		let cipher = box.encrypt(message)
		
		let decrypted = box.decrypt(cipher) ?? ""
		print("Decrypted: \(decrypted) \(message)")
		XCTAssert(decrypted == message)
	}
	
	func testSignature() {
		let keypair = SigningKeyPair()
		
		let message = "1231231123"
		let signedMessage = keypair.sign(message: message.data(using: .utf8)!)
		
		let unsignedMessage = String(data: keypair.verifySignature(signedMessage) ?? Data(), encoding: .utf8) ?? ""
		XCTAssert(unsignedMessage == message)
	}
	
	func testBox() {
		let localBox = Box()
		let remoteBox = Box()
		
		let message = "Correct Horse Battery Staple!"
		let messageBytes = Array(message.utf8)
		
		let encrypted = try? remoteBox.encrypt(message: messageBytes, localBox: localBox)
		XCTAssert(encrypted != nil)
		let decrypted = try? localBox.decrypt(message: encrypted!, remoteBox: remoteBox)
		XCTAssert(decrypted != nil)
		
		let decryptedMessage = String(bytes: decrypted!, encoding: .utf8)
		XCTAssert(decryptedMessage == "Correct Horse Battery Staple!")
	}
}
