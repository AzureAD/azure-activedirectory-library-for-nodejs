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

require('date-utils');
var jwtConstants = require('./constants').Jwt;
var jwt = require('jwt-simple');
var Logger = require('./log').Logger;

function SelfSignedJwt(callContext, authority, clientId, certificate) {
  this._log = new Logger('SelfSignedJwt', callContext._logContext);
  this._callContext = callContext;

  this._tokenEndpoint = authority.tokenEndpoint;
  this._certificate = certificate;
  this._clientId = clientId;
}

SelfSignedJwt.prototype.create = function() {
	var now = new Date();
//	var expires = Date.now().add({ minutes: jwtConstants.SELF_SIGNED_JWT_LIFETIME });
  var expires = (new Date()).addMinutes(jwtConstants.SELF_SIGNED_JWT_LIFETIME);

	var jwtPayload = {};
	jwtPayload[jwtConstants.AUDIENCE] = this._authority;
	jwtPayload[jwtConstants.ISSUER] = this._clientId;
	jwtPayload[jwtConstants.SUBJECT] = this._clientId;
	jwtPayload[jwtConstants.NOT_BEFORE] = now.getTime();
	jwtPayload[jwtConstants.EXPIRES_ON] = expires.getTime();

	return jwt.encode(jwtPayload, this._certificate, 'RS256');
};

module.exports.SelfSignedJwt = SelfSignedJwt;