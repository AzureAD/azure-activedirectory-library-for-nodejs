/*
 * @copyright
 * Copyright © Microsoft Open Technologies, Inc.
 *
 * All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: *www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 */
'use strict';

var constants = require('./constants');
var Logger = require('./log').Logger;
var Mex = require('./mex');
var OAuth2Client = require('./oauth2client');

var OAuth2Parameters = constants.OAuth2.Parameters;
var TokenResponseFields = constants.TokenResponseFields;
var OAuth2GrantType = constants.OAuth2.GrantType;
var OAuth2Scope = constants.OAuth2.Scope;

/**
 * Constructs a new TokenRequest object.
 * @constructor
 * @private
 * @param {object} callContext Contains any context information that applies to the request.
 * @param {AuthenticationContext} authenticationContext
 * @param {string} resource
 * @param {string} clientId
 */
// TODO: probably need to modify the parameter list. 
function CodeRequest(callContext, authenticationContext, clientId, resource) {
    this._log = new Logger('TokenRequest', callContext._logContext);
    this._callContext = callContext;
    this._authenticationContext = authenticationContext;
    this._resource = resource;
    this._clientId = clientId;
    //this._redirectUri = redirectUri;
    
    // This should be set at the beginning of getToken
    // functions that have a userId.
    this._userId = null;
    
    this._userRealm = null;
}
