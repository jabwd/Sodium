//
//  AWSSignature.swift
//  Sodium
//
//  Created by Antwan van Houdt on 07/08/2018.
//

import Foundation

public struct AWSSignature {
	public let secretKey: String
	public let accessKey: String
	public let region: String
	public let service: String

	private let iso8601Formatter: DateFormatter = {
		let formatter = DateFormatter()
		formatter.calendar = Calendar(identifier: .iso8601)
		formatter.locale = Locale(identifier: "en_US_POSIX")
		formatter.timeZone = TimeZone(secondsFromGMT: 0)
		formatter.dateFormat = "yyyyMMdd'T'HHmmssXXXXX"
		return formatter
	}()

	private func iso8601() -> (full: String, short: String) {
		let date = iso8601Formatter.string(from: Date())
		let index = date.index(date.startIndex, offsetBy: 8)
		let shortDate = date[date.startIndex..<index]
		return (full: date, short: String(shortDate))
	}

	public init(request: URLRequest, service: String, secretKey: String, accessKey: String, region: String) {
		self.secretKey = secretKey
		self.accessKey = accessKey
		self.region = region
		self.service = service
	}

	public func signRequest(_ request: URLRequest) -> URLRequest? {
		var signedRequest = request
		let date = iso8601()

		guard let payload = signedRequest.httpBody else { return nil }
		guard let url = signedRequest.url else { return nil }
		guard let host = url.host else { return nil }

		signedRequest.addValue("binary/octet-stream", forHTTPHeaderField: "Content-Type")
		signedRequest.addValue(host, forHTTPHeaderField: "Host")
		signedRequest.addValue(date.full, forHTTPHeaderField: "X-Amz-Date")
		guard let headers = signedRequest.allHTTPHeaderFields,
			let method = signedRequest.httpMethod else { return nil }

		let signedHeaders = headers.map { $0.key.lowercased() }.sorted().joined(separator: ";")

		let bodyHash = [UInt8](payload).sha256

		let canonicalRequestString: String = [
			method,
			url.path,
			url.query ?? "",
			headers.map { $0.key.lowercased() + ":" + $0.value }.sorted().joined(separator: "\n"),
			"",
			signedHeaders,
			bodyHash.toHexString()
		].joined(separator: "\n")
		let canonicalRequestHashBytes = [UInt8](canonicalRequestString.utf8).sha256
		signedRequest.setValue(bodyHash.toHexString(), forHTTPHeaderField: "x-amz-content-sha256")

		let credential = [date.short, region, service, "aws4_request"].joined(separator: "/")

		let stringToSign = [
			"AWS4-HMAC-SHA256",
			date.full,
			credential,
			canonicalRequestHashBytes.toHexString()
		].joined(separator: "\n")

		guard let signature = signStringToSign(stringToSign, shortDateString: date.short) else {
			return nil
		}

		// swiftlint:disable line_length
		let authorization = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(credential), SignedHeaders=\(signedHeaders), Signature=\(signature)"
		// swiftlint:enable line_length

		signedRequest.addValue(authorization, forHTTPHeaderField: "Authorization")

		return signedRequest
	}

	private func signStringToSign(_ stringToSign: String, shortDateString: String) -> String? {
		let startingKey = "AWS4\(secretKey)"

		let startingKeyBytes = [UInt8](startingKey.utf8)

		let data = region.data(using: .utf8)!

		let keyDate = Hash.hmacSHA256([UInt8](shortDateString.utf8), key: startingKeyBytes)
		let keyRegion = Hash.hmacSHA256([UInt8](data), key: keyDate)
		let keyService = Hash.hmacSHA256([UInt8](service.utf8), key: keyRegion)
		let keySigning = Hash.hmacSHA256([UInt8]("aws4_request".utf8), key: keyService)

		let signature = Hash.hmacSHA256([UInt8](stringToSign.utf8), key: keySigning)
		return signature.toHexString()
	}
}
