--[[
Set of crypto functions built on basexx and openssl capabilities
--]]

-- Dependencies
local logger = require 'LoggingUtils'
local baseutils = require 'basexx'
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local kdf = require "openssl.kdf"
local pkey = require "openssl.pkey"
local digest = require "openssl.digest"
local hmac = require "openssl.hmac"
local ber = require "ber"

local CryptoLite = {}

--[[
    ============================================================================
    Internal utility functions (not exported)
    ============================================================================
--]]


--[[
    Derives a 256-bit key from a passphrase using PBKDF2
    @param passphrase: The passphrase to derive key from
    @param salt: Salt for key derivation (optional, will be generated if not provided)
    @param iterations: Number of iterations (default: 100000)
    @return key, salt: The derived key and salt used
--]]
local function deriveKey(passphrase, salt, iterations)
    iterations = iterations or 100000
    salt = salt or rand.bytes(16)
    
    local params = {
        type = "PBKDF2",
        pass = passphrase,
        salt = salt,
        iter = iterations,
        md = "sha256",
        outlen = 32
    }
    local key = kdf.derive(params)
    
    return key, salt
end

local function removeLeadingZeros(data)
    local leadingZeros = 0
    for i = 1, #data do
        if data:byte(i) ~= 0 then
            break
        end
        leadingZeros = leadingZeros + 1
    end
    return data:sub(leadingZeros + 1)
end

local function padIfSigned(n)
    local result = ''
    -- check the leading byte of byte string n, and if it is > 127 then prepend 0x00 to n
    local leadingByte = n:byte(1)
    if (leadingByte > 127) then
        result = "\x00" .. n
    else
        result = n
    end
    return result
end

local function getRandSFromOpenSSLECSignature(sigBytes)
    local r = nil
    local s = nil

    local decodeResult = ber.decode(sigBytes)
    if (decodeResult ~= nil and decodeResult["class"] == 0 and decodeResult["type"] == 16 and decodeResult["data"] ~= nil
        and decodeResult["children"] ~= nil and #decodeResult["children"] == 2
        and decodeResult["children"][1] ~= nil and decodeResult["children"][2] ~= nil
        and decodeResult["children"][1]["class"] == 0 and decodeResult["children"][2]["class"] == 0
        and decodeResult["children"][1]["type"] == 2 and decodeResult["children"][2]["type"] == 2
    ) then
        r = removeLeadingZeros(decodeResult["children"][1]["data"])
        s = removeLeadingZeros(decodeResult["children"][2]["data"])

        if (#r ~= 32 or #s ~= 32) then
            logger.debugLog("CryptoLite:getRandSFromOpenSSLECSignature unexpected r and s lengths")
            r = nil
            s = nil
        end
    else
        logger.debugLog("CryptoLite:getRandSFromOpenSSLECSignature unexpected decodeResult")
    end

    return r, s
end

local function getOpenSSLECSignatureFromRandS(r,s)
    --
    -- basically reverse the steps of getRandSFromOpenSSLECSignature()
    --
    local finalR = padIfSigned(r)
    local finalS = padIfSigned(s)

    local berR = ber.encode({ 
        type = ber.Types.INTEGER,
        data = finalR
    })
    local berS = ber.encode({ 
        type = ber.Types.INTEGER,
        data = finalS
    })
    local berSeq = ber.encode({ 
    type = ber.Types.SEQUENCE,
        data = berR .. berS
     })

    return berSeq
end

--[[
    ============================================================================
    BASE64 ENCODING/DECODING FUNCTIONS (Public APIs)
    ============================================================================
--]]

--[[
    Base64 encode a string
    @param data: The data to encode
    @return encoded: Base64-encoded string
--]]
function CryptoLite.base64Encode(data)
    return baseutils.to_base64(data)
end

--[[
    Base64 decode a string
    @param data: Base64-encoded string
    @return decoded: Decoded string
--]]
function CryptoLite.base64Decode(data)
    return baseutils.from_base64(data)
end

--[[
    Base64URL encode a string (URL-safe base64 encoding used in JWT)
    @param data: The data to encode
    @return encoded: Base64URL-encoded string
--]]
function CryptoLite.base64URLEncode(data)
    return baseutils.to_url64(data)
end

--[[
    Base64URL decode a string (URL-safe base64 decoding used in JWT)
    @param data: Base64URL-encoded string
    @return decoded: Decoded string
--]]
function CryptoLite.base64URLDecode(data)
        return baseutils.from_url64(data)
end


--[[
    ============================================================================
    Symmetric key encryption and decryption
    ============================================================================
--]]

--[[
    Symmetric Encryption using AES-256-GCM
    @param plaintext: The string to encrypt
    @param key: Encryption key (string). If less than 32 bytes, will be derived using PBKDF2
    @return encrypted: Base64-encoded encrypted data with format: salt:iv:tag:ciphertext
--]]
function CryptoLite.encryptSymmetric(plaintext, key)
    if not plaintext or not key then
        error("plaintext and key are required")
    end
    
    -- Derive a proper 256-bit key if needed
    local encKey, salt
    if #key < 32 then
        encKey, salt = deriveKey(key)
    else
        encKey = key:sub(1, 32)
        salt = rand.bytes(16)
    end
    
    -- Generate random IV (12 bytes for GCM)
    local iv = rand.bytes(12)
    
    -- Create cipher
    local c = cipher.new("aes-256-gcm")
    
    -- Encrypt
    local ciphertext = c:encrypt(encKey, iv):final(plaintext)
    local tag = c:getTag(16)
    
    -- Combine salt:iv:tag:ciphertext and encode
    local combined = salt .. iv .. tag .. ciphertext
    return CryptoLite.base64Encode(combined)
end

--[[
    Symmetric Decryption using AES-256-GCM
    @param encrypted: Base64-encoded encrypted data from encryptSymmetric
    @param key: Decryption key (same as used for encryption)
    @return plaintext: The decrypted string
--]]
function CryptoLite.decryptSymmetric(encrypted, key)
    if not encrypted or not key then
        error("encrypted data and key are required")
    end
    
    -- Decode from base64
    local combined = CryptoLite.base64Decode(encrypted)
    
    -- Extract components
    local salt = combined:sub(1, 16)
    local iv = combined:sub(17, 28)
    local tag = combined:sub(29, 44)
    local ciphertext = combined:sub(45)
    
    -- Derive the same key
    local encKey
    if #key < 32 then
        encKey = deriveKey(key, salt)
    else
        encKey = key:sub(1, 32)
    end
    
    -- Create cipher
    local c = cipher.new("aes-256-gcm")
    
    -- Decrypt
    c:decrypt(encKey, iv)
    c:setTag(tag)
    local plaintext = c:final(ciphertext)
    
    return plaintext
end

--[[
    ============================================================================
    Asymmetric key generation
    ============================================================================
--]]

--[[
    Generate RSA key pair
    @param bits: Key size in bits (default: 2048, recommended: 2048 or 4096)
    @return publicKeyPEM, privateKeyPEM: The generated key pair in PEM format
--]]
function CryptoLite.generateRSAKeyPair(bits)
    bits = bits or 2048

    local genParams = {
        type = "RSA",
        bits = bits,
        e = 65537
    }
    
    local key = pkey.new(genParams)
    local publicKeyPEM = key:toPEM("public")
    local privateKeyPEM = key:toPEM("private")
    
    return publicKeyPEM, privateKeyPEM
end

--[[
    Generate ECDSA key pair
    @param curve: Curve name (default: "prime256v1", options: "prime256v1", "secp384r1", "secp521r1")
    @return publicKeyPEM, privateKeyPEM: The generated key pair in PEM format
--]]
function CryptoLite.generateECDSAKeyPair(curve)
    curve = curve or "prime256v1"

    local genParams = {
        type = "EC",
        curve = curve
    }
    
    local key = pkey.new(genParams)
    local publicKeyPEM = key:toPEM("public")
    local privateKeyPEM = key:toPEM("private")
    
    return publicKeyPEM, privateKeyPEM
end

--[[
    ============================================================================
    DIGITAL SIGNATURE / VALIDATION FUNCTIONS (JWT-compatible: RS256, ES256, HS256)
    ============================================================================
--]]

--[[
    Sign data using RSA-SHA256 (RS256 - JWT algorithm)
    @param data: The data to sign
    @param privateKeyPEM: RSA private key in PEM format
    @return signature: Base64URL-encoded signature
--]]
function CryptoLite.signRS256(data, privateKeyPEM)
    if not data or not privateKeyPEM then
        error("CryptoLite.signRS256: data and privateKeyPEM are required")
    end
    
    -- Load private key
    local privKey = pkey.new(privateKeyPEM)
    
    -- Create SHA-256 digest of the data
    local md = digest.new("sha256")
    
    -- Sign the hash of data
    local signature = privKey:sign(md:update(data))
    
    return CryptoLite.base64URLEncode(signature)
end

--[[
    Verify RSA-SHA256 signature (RS256 - JWT algorithm)
    @param data: The original data that was signed
    @param signature: Base64URL-encoded signature
    @param publicKeyPEM: RSA public key in PEM format
    @return valid: Boolean indicating if signature is valid
--]]
function CryptoLite.verifyRS256(data, signature, publicKeyPEM)
    if not data or not signature or not publicKeyPEM then
        error("CryptoLite.verifyRS256: data, signature, and publicKeyPEM are required")
    end
    
    -- Decode signature from base64url
    local sig = CryptoLite.base64URLDecode(signature)
    
    -- Load public key
    local pubKey = pkey.new(publicKeyPEM)
    
    -- Create SHA-256 digest of the data
    local md = digest.new("sha256")
    
    -- Verify signature
    local valid = pubKey:verify(sig, md:update(data))
    
    return valid
end

--[[
    Sign data using ECDSA-SHA256 (ES256 - JWT algorithm)
    @param data: The data to sign
    @param privateKeyPEM: EC private key in PEM format
    @return signature: Base64URL-encoded signature
--]]
function CryptoLite.signES256(data, privateKeyPEM)
    if not data or not privateKeyPEM then
        error("CryptoLite.signES256: data and privateKeyPEM are required")
    end
    
    -- Load private key
    local privKey = pkey.new(privateKeyPEM)
    
    -- Create SHA-256 digest of the data
    local md = digest.new("sha256")
    
    -- Sign the hash of data
    local sigBytes = privKey:sign(md:update(data))

    -- extract R, S without padding from the OpenSSL formatted signature
    -- then concatenate and base64urlencode to create JWT signature
    local r, s = getRandSFromOpenSSLECSignature(sigBytes)

    return CryptoLite.base64URLEncode(r .. s)
end

--[[
    Verify ECDSA-SHA256 signature (ES256 - JWT algorithm)
    @param data: The original data that was signed
    @param signature: Base64URL-encoded signature
    @param publicKeyPEM: EC public key in PEM format
    @return valid: Boolean indicating if signature is valid
--]]
function CryptoLite.verifyES256(data, signature, publicKeyPEM)
    if not data or not signature or not publicKeyPEM then
        error("CryptoLite.verifyES256: data, signature, and publicKeyPEM are required")
    end
    
    -- Re-create OpenSSL compatible signature format from JWT signature format
    local sig = CryptoLite.base64URLDecode(signature)
    if (#sig ~= 64) then
        error("CryptoLite.verifyES256: signature is not 64 bytes long")
    end
    local r = string.sub(sig, 1, 32)
    local s = string.sub(sig, 33, 64)
    local opensslSig = getOpenSSLECSignatureFromRandS(r,s)

    -- Load public key
    local pubKey = pkey.new(publicKeyPEM)
    
    -- Create SHA-256 digest
    local md = digest.new("sha256")
    
    -- Verify signature over digest of the data
    local valid = pubKey:verify(opensslSig, md:update(data))
    
    return valid
end


--[[
    Sign data using HMAC-SHA256 (HS256 - JWT algorithm)
    @param data: The data to sign
    @param secret: Shared secret key
    @return signature: Base64URL-encoded HMAC signature
--]]
function CryptoLite.signHS256(data, secret)
    if not data or not secret then
        error("CryptoLite.signHS256: data and secret are required")
    end
    
    -- Create HMAC with SHA-256
    local h = hmac.new(secret, "sha256")
    local signature = h:final(data)
    
    return CryptoLite.base64URLEncode(signature)
end

--[[
    Verify HMAC-SHA256 signature (HS256 - JWT algorithm)
    @param data: The original data that was signed
    @param signature: Base64URL-encoded HMAC signature
    @param secret: Shared secret key
    @return valid: Boolean indicating if signature is valid
--]]
function CryptoLite.verifyHS256(data, signature, secret)
    if not data or not signature or not secret then
        error("CryptoLite.verifyHS256: data, signature, and secret are required")
    end
    
    -- Compute expected signature
    local expectedSignature = CryptoLite.signHS256(data, secret)
    
    -- Constant-time comparison to prevent timing attacks
    local sig = CryptoLite.base64URLDecode(signature)
    local expected = CryptoLite.base64URLDecode(expectedSignature)
    
    if #sig ~= #expected then
        return false
    end
    
    local result = 0
    for i = 1, #sig do
        result = result | (string.byte(sig, i) ~ string.byte(expected, i))
    end
    
    return result == 0
end

return CryptoLite
