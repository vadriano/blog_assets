--[[
        NOTE: This transformation rule requires a fix to WebSEAL such that the Session attribute is
        correctly made available to postauthn transformation rules. Without that fix, this will not work.
        There is trace at the start of the rule that will print out if the rule detects you are running
        on a version of WebSEAL that does not have the fix.

        A transformation that runs at the conclusion of each authentication method that it is configured
        against to propagate forward a set of credential attributes during stepup operations.

        The way this works is that a session memory cache is used to collect the attributes to preserve. 
        
        It is populated cumulatively at the end of every mechanism in a postauthn transformation.
        There is no pruning of attributes at any stage.
        At the end of each authentication method, any attributes that are in the memory cache that are 
        not seen in the credential are added back in.

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        preserve_credential_attributes = preserve_credential_attributes.lua

        # Add/remove request-match lines for each type of authentication mechanism you 
        # have in your WebSEAL.
        [http-transformations:preserve_credential_attributes]
        request-match = postauthn:ssl
        request-match = postauthn:password
        request-match = postauthn:ext-auth-interface

        =============		
--]]

local cjson = require "cjson"
local logger = require "LoggingUtils"

-- list of attribute names that we want to preserve through stepup operations
local ATTR_NAMES = { "method" }

-- MERGE_STRATEGY determines whether to add, keep, or replace an attribute 
-- in the memory cache with any that appears in "current" credential after 
-- a stepup has occured. This might result in multi-valued attributes in the cred
-- if any of the attrs in ATTR_NAMES is already multi-valued, or if using the 
-- "add" merge strategy and an attributes value changes between login methods.
-- In this implementation, the same merge strategy applies to all attributes.

-- the value should be one of "add", "keep", "replace"
local MERGE_STRATEGY = "add"

-- name of session attribute that stores the JSON of the table of 
-- attributes we are preserving through stepup operations
local SESSION_ATTROBJ_NAME = "PRESERVE_SESSION_ATTRIBUTES"


local function getSessionAttrsObj()
    local sessionAttrObjStr = (Session.getSessionAttribute(SESSION_ATTROBJ_NAME) or "{}")
    --local sessionAttrObjStr = '{"method":["SSL Client Certificate"]}'
    return cjson.decode(sessionAttrObjStr)
end

local function saveSessionAttrsObj(o)
    Session.setSessionAttribute(SESSION_ATTROBJ_NAME, cjson.encode(o))
end

--[[
Checks if a table has a value
--]]
local function hasValue (tab, val)
    if tab == nil then
        return false
    end
    for k,v in ipairs(tab) do
        if v == val then
            return true
        end
    end

    return false
end

--[[
Works around an issue where the IVIA Session apis that return an "array" are not correctly indexed from 1.
The problem is that you cannot call ipairs on those arrays as the 0-index first element will be skipped.
This rebuilds the table representing the array from 0-indexed to 1-indexed, in such a way that when the
issue is fixed in IVIA, this code will continue to work without breaking anything.

It does this by taking all the indexes that are in tab, sorting them, then constructing a new table
with the values from tab in the sorted order of whatever their original indexes were.
--]]
local function fixArray(tab)
    -- sort the existing indexes of tab, which may be 0-based, or 1-based, or based on any other sortable sequence
    local indexes = {}
    for i,v in pairs(tab) do
        table.insert(indexes, i)
    end
    table.sort(indexes)

    -- iterate over the sorted indexes, and build a new properly 1-indexed table as the resulting array
    local result = {}
    for i,v in ipairs(indexes) do
        table.insert(result, tab[v])
    end
    return result
end



logger.debugLog("preserve_credential_attributes called during stage: " .. Control.getStage())
if (Control.getStage() == "postauthn") then
    -- detect if WebSEAL has the fix for making the Session available to the postauthn transformation state
    if (Session.getSessionId() == nil) then
        logger.debugLog("preserve_credential_attributes: ******** ERROR: The version of WebSEAL you are running needs a fix to make the Session information available to the postauthn Lua transformation stage")
    else
        logger.debugLog("preserve_credential_attributes.AZN_CRED_AUTH_METHOD: " .. Session.getCredentialAttribute("AZN_CRED_AUTH_METHOD"))

        -- first lets update the memory cache with any attribute values that are 
        -- currently in the credential after this authentication mechanism has run
        local attrsObj = getSessionAttrsObj()
        logger.debugLog("preserve_credential_attributes starting attrsObj: " .. cjson.encode(attrsObj))
        logger.debugLog(Control.dumpContext())

        for i,v in ipairs(ATTR_NAMES) do
            -- we only have something to look at if the credential contains one or more values for this attribute
            if (Session.containsCredentialAttribute(v)) then

                local valuesArray = fixArray(Session.getMvCredentialAttribute(v))

                if (MERGE_STRATEGY == "replace") then
                    -- if the merge strategy is replace then just set the memory values to that of the credential
                    attrsObj[v] = valuesArray
                elseif (MERGE_STRATEGY == "keep") then
                    -- they get added to the memory cache only if the memory cache does not already have a value for this attribute
                    if (attrsObj[v] == nil) then
                        --logger.debugLog("preserve_credential_attributes establishing memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(Session.getMvCredentialAttribute(v)))
                        attrsObj[v] = valuesArray
                    end
                else
                    -- merge strategy is add - either establish entry in memory cache or add any new values to the existing list (that are not already present)
                    if (attrsObj[v] == nil) then
                        logger.debugLog("preserve_credential_attributes establishing memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(valuesArray))
                        attrsObj[v] = valuesArray
                    else
                        --logger.debugLog("preserve_credential_attributes merging memory cache for attr: " .. v .. " with value: " .. logger.dumpAsString(attrsObj[v]) .. " and current credential values: " .. logger.dumpAsString(valuesArray))
                        local currentValues = attrsObj[v]
                        for i2,v2 in ipairs(valuesArray) do
                            if (not hasValue(currentValues, v2)) then
                                table.insert(currentValues, v2)
                            end
                        end
                        attrsObj[v] = currentValues
                        logger.debugLog("preserve_credential_attributes merged memory cache for attr: " .. v .. " is: " .. logger.dumpAsString(attrsObj[v]))
                    end
                end
            end
        end

        -- store whatever we ended up with in the session memory
        logger.debugLog("preserve_credential_attributes ending attrsObj: " .. cjson.encode(attrsObj))
        saveSessionAttrsObj(attrsObj)

        -- set all the attrs in attrsObj in the credential
        for k,v in pairs(attrsObj) do
            Session.setCredentialAttribute(k,v)
        end
    end
end
