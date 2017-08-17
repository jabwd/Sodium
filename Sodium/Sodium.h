//
//  Sodium.h
//  Sodium
//
//  Created by Antwan van Houdt on 17/08/2017.
//
//

#import <UIKit/UIKit.h>

//! Project version number for Sodium.
FOUNDATION_EXPORT double SodiumVersionNumber;

//! Project version string for Sodium.
FOUNDATION_EXPORT const unsigned char SodiumVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <PublicHeader.h>


#include "core.h"
#include "crypto_aead_aes256gcm.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_auth.h"
#include "crypto_auth_hmacsha256.h"
#include "crypto_auth_hmacsha512.h"
#include "crypto_auth_hmacsha512256.h"
#include "crypto_box.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_core_hsalsa20.h"
#include "crypto_core_hchacha20.h"
#include "crypto_core_salsa20.h"
#include "crypto_core_salsa2012.h"
#include "crypto_core_salsa208.h"
#include "crypto_generichash.h"
#include "crypto_generichash_blake2b.h"
#include "crypto_hash.h"
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"
#include "crypto_onetimeauth.h"
#include "crypto_onetimeauth_poly1305.h"
#include "crypto_pwhash.h"
#include "crypto_pwhash_argon2i.h"
#include "crypto_pwhash_scryptsalsa208sha256.h"
#include "crypto_scalarmult.h"
#include "crypto_scalarmult_curve25519.h"
#include "crypto_secretbox.h"
#include "crypto_secretbox_xsalsa20poly1305.h"
#include "crypto_shorthash.h"
#include "crypto_shorthash_siphash24.h"
#include "crypto_sign.h"
#include "crypto_sign_ed25519.h"
#include "crypto_stream.h"
#include "crypto_stream_aes128ctr.h"
#include "crypto_stream_chacha20.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_salsa2012.h"
#include "crypto_stream_salsa208.h"
#include "crypto_stream_xsalsa20.h"
#include "crypto_verify_16.h"
#include "crypto_verify_32.h"
#include "crypto_verify_64.h"
#include "randombytes.h"
#ifdef __native_client__
# include "randombytes_nativeclient.h"
#endif
#include "randombytes_salsa20_random.h"
#include "randombytes_sysrandom.h"
#include "runtime.h"
#include "utils.h"
#include "version.h"
