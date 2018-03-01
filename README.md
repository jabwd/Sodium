# Sodium
libsodium framework for iOS with a basic Swift API layer ( more libsodium coverage will follow in future updates ).

### SecretBox

```
let box = SecretBox() // automatically generates the key for you

or:

// Returns nil if the key is not of sufficient size
let box = SecretBox(keyBytes)?

box.encrypt("Blabla")
box.decrypt(message)?
```

### Password hashing

libsodium password hashing uses the memory intensive `argon2` algorithm.

The parameters are currently configured for 20MB of memory usage and 6 operations. It is a good idea to test for perfomance if this is too slow for your target system.
On my system this tested at an average of around `1 second`.

##### Usage

```
let passwordHash = Hash.createPasswordHash("Correct Horse Battery Staple!")

let result = Hash.verifyPassword(password, passwordHash)
```

### Blake2 hashing

Blake2 hashing is useful for large amounts of data for fast hashing. It should not be used for sensitive content ( like passwords ) as it would be rather easy to bruteforce.

Usage:

```
let key = Data.random(Hash.keySize)
let hash = Hash.blake(inputData, key: key)
```
