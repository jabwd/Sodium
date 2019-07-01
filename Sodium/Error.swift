//
//  Error.swift
//  Sodium
//
//  Created by Antwan van Houdt on 26/02/2018.
//

public enum SodiumError: Error {
	case invalidPublicKey
	case invalidSecretKey

	case invalidSignature

	case invalidBoxCipherText
	case boxDecryptionFailed
	case boxEncryptionFailed
}
