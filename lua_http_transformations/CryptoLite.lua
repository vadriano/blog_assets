--[[
Set of crypto functions built on basexx and openssl capabilities
--]]

-- Dependencies
local baseutils = require 'basexx'
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local kdf = require "openssl.kdf"

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
    Symmetric key encryption end decryption
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

return CryptoLite
