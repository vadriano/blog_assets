--[[
        A HTTP transformation that can is used to test the cryptolite functions

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        testcryptolite = testcryptolite.lua

        [http-transformations:testcryptolite]
        request-match = request:GET /testcryptolite *
        =============
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require 'CryptoLite'
local cjson = require "cjson"

function preBlockWithTitle(title, text)
        return "<div style='border: 1px solid black; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end



logger.debugLog("testcryptolite")

local rspBody = "<html><body>"

-- symmetric key encryption and decryption
local symmetricKey = "mysecretkey"
local plainText = "mysecretdata"
local cipherText = cryptoLite.encryptSymmetric(plainText, symmetricKey)
local decryptedText = cryptoLite.decryptSymmetric(cipherText, symmetricKey)
local symmetricText = "symmetricKey: " .. symmetricKey .. "\n" .. "plainText: " .. plainText .. "\n" .. "cipherText: " .. cipherText .. "\n" .. "decryptedText: " .. decryptedText
rspBody = rspBody .. preBlockWithTitle("Symmetric key encryption/decryption", symmetricText)

-- RSA 2048 bit key generation
local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
rspBody = rspBody .. preBlockWithTitle("RSA Public key", rsaPublicKey) .. preBlockWithTitle("RSA Private key", rsaPrivateKey)

-- EC key generation
local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
rspBody = rspBody .. preBlockWithTitle("EC Public key", ecPublicKey) .. preBlockWithTitle("EC Private key", ecPrivateKey)

-- JWT signature with RS256
local jwtHeader = {
        alg = "RS256",
        typ = "JWT"
}
local jwtClaims = {
        sub = "testuser"
}
local signatureBaseString = cryptoLite.base64URLEncode(cjson.encode(jwtHeader)).."."..cryptoLite.base64URLEncode(cjson.encode(jwtClaims))
local signatureB64U = cryptoLite.signRS256(signatureBaseString, rsaPrivateKey)
local rsaJWTStr = signatureBaseString.."."..signatureB64U
rspBody = rspBody .. preBlockWithTitle("JWT with RS256", rsaJWTStr)

local verifyResult = cryptoLite.verifyRS256(signatureBaseString, signatureB64U, rsaPublicKey)
rspBody = rspBody .. preBlockWithTitle("JWT RS256 signature validation", "verifyResult: " .. logger.dumpAsString(verifyResult))

-- JWT signature with ES256
jwtHeader["alg"] = "ES256"
signatureBaseString = cryptoLite.base64URLEncode(cjson.encode(jwtHeader)).."."..cryptoLite.base64URLEncode(cjson.encode(jwtClaims))
signatureB64U = cryptoLite.signES256(signatureBaseString, ecPrivateKey)
local ecJWTStr = signatureBaseString.."."..signatureB64U
rspBody = rspBody .. preBlockWithTitle("JWT with ES256", ecJWTStr)

local verifyResult = cryptoLite.verifyES256(signatureBaseString, signatureB64U, ecPublicKey)
rspBody = rspBody .. preBlockWithTitle("JWT ES256 signature validation", "verifyResult: " .. logger.dumpAsString(verifyResult))

-- JWT signature with HS256
local hmacSecret = "password"
jwtHeader["alg"] = "HS256"
signatureBaseString = cryptoLite.base64URLEncode(cjson.encode(jwtHeader)).."."..cryptoLite.base64URLEncode(cjson.encode(jwtClaims))
signatureB64U = cryptoLite.signHS256(signatureBaseString, hmacSecret)
local hmacJWTStr = signatureBaseString.."."..signatureB64U
rspBody = rspBody .. preBlockWithTitle("JWT with HS256", hmacJWTStr)

verifyResult = cryptoLite.verifyHS256(signatureBaseString, signatureB64U, hmacSecret)
rspBody = rspBody .. preBlockWithTitle("JWT HS256 signature validation", "verifyResult: " .. logger.dumpAsString(verifyResult))


rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

