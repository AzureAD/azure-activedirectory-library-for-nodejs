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

var jwtConstants = require('./constants').Jwt;
var Logger = require('./log').Logger;
var util = require('./util');

var crypto = require('crypto');
require('date-utils');
var uuid = require('node-uuid');

function SelfSignedJwt(callContext, authority, clientId) {
  this._log = new Logger('SelfSignedJwt', callContext._logContext);
  this._callContext = callContext;

  this._tokenEndpoint = authority.tokenEndpoint;
  this._clientId = clientId;
}

SelfSignedJwt.prototype._createHeader = function(thumbprint) {
    var header = { typ: 'JWT', alg: 'RS256', x5t : thumbprint };

    this._log.verbose('Creating self signed JWT header.  Thumbprint: ' + thumbprint);

    return header;
};

SelfSignedJwt.prototype._createPayload = function() {
  var now = new Date();
  var expires = (new Date()).addMinutes(jwtConstants.SELF_SIGNED_JWT_LIFETIME);

  this._log.verbose('Creating self signed JWT payload.  Expires: ' + expires + ' NotBefore: ' + now);

  var jwtPayload = {};
  jwtPayload[jwtConstants.AUDIENCE] = this._authority;
  jwtPayload[jwtConstants.ISSUER] = this._clientId;
  jwtPayload[jwtConstants.SUBJECT] = this._clientId;
  jwtPayload[jwtConstants.NOT_BEFORE] = now.getTime();
  jwtPayload[jwtConstants.EXPIRES_ON] = expires.getTime();
  jwtPayload[jwtConstants.JWT_ID] = uuid.v4();

  return jwtPayload;
};

SelfSignedJwt.prototype.create = function(certificate, thumbprint) {
  var header = this._createHeader(thumbprint);
  var payload = this._createPayload();

  var headerString = util.base64EncodeStringUrlSafe(JSON.stringify(header));
  var payloadString = util.base64EncodeStringUrlSafe(JSON.stringify(payload));
  var stringToSign = headerString + '.' + payloadString;

  var signature = util.base64EncodeStringUrlSafe(crypto.createSign('RSA-SHA256').update(stringToSign).sign(certificate, 'base64'));

	return stringToSign + '.' + signature;
};

module.exports.SelfSignedJwt = SelfSignedJwt;