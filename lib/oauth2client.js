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

var _ = require('underscore');
require('date-utils');  // Adds a number of convenience methods to the builtin Date object.
var querystring = require('querystring');
var uuid = require('node-uuid');
var request = require('request');
var url = require('url');

var constants = require('./constants');
var Logger = require('./log').Logger;
var util = require('./util');

var OAuth2Parameters = constants.OAuth2.Parameters;
var OAuth2ResponseParameters = constants.OAuth2.ResponseParameters;
var IdTokenMap = constants.OAuth2.IdTokenMap;
var TokenResponseFields = constants.TokenResponseFields;
var IdTokenFields = constants.IdTokenFields;


var TOKEN_RESPONSE_MAP = {};
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.TOKEN_TYPE] = TokenResponseFields.TOKEN_TYPE;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ACCESS_TOKEN] = TokenResponseFields.ACCESS_TOKEN;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.REFRESH_TOKEN] = TokenResponseFields.REFRESH_TOKEN;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.CREATED_ON] = TokenResponseFields.CREATED_ON;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.EXPIRES_ON] = TokenResponseFields.EXPIRES_ON;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.EXPIRES_IN] = TokenResponseFields.EXPIRES_IN;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.RESOURCE] = TokenResponseFields.RESOURCE;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ERROR] = TokenResponseFields.ERROR;
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ERROR_DESCRIPTION] = TokenResponseFields.ERROR_DESCRIPTION;

/**
 * Constructs an instances of OAuth2Client
 * @constructor
 * @private
 * @param {object} callContext Contains any context information that applies to the request.
 * @param {string|url} authority  An url that points to an authority.
 */
function OAuth2Client(callContext, authority) {
  this._tokenEndpoint = authority.tokenEndpoint;
  this._log = new Logger('OAuth2Client', callContext._logContext);
  this._callContext = callContext;
}

/**
 * Constructs an OAuth 2.0 token request url.
 * @private
 * @return {URL}
 */
OAuth2Client.prototype._createTokenUrl = function () {
  var tokenUrl = url.parse(this._tokenEndpoint);

  var parameters = {};
  parameters.slice = 'testslice';
  parameters[OAuth2Parameters.AAD_API_VERSION] = '1.0';

  tokenUrl.search = querystring.stringify(parameters);

  return tokenUrl;
};

/**
 * @private
 * @param {object}   obj         An object in which integer values may reside.
 * @param {array}    keys        An array of strings that specify keys in which integers may need parsing.
 */
OAuth2Client.prototype._parseOptionalInts = function (obj, keys) {
  var self = this;
  keys.forEach(function(element) {
    if (_.has(obj, element)) {
      obj[element] = parseInt(obj[element], 10);
      if (isNaN(obj[element])) {
        throw self._log.createError(element + ' could not be parsed as an int.');
      }
    }
  });
};

/**
 * Cracks a JWS encoded JWT into it's three parts.
 * @param  {string} jwtToken The token to crack.
 * @return {object}          The three JWS parts, header, JWSPayload, and JWSSig, or undefined.
 */
OAuth2Client.prototype._crackJwt = function(jwtToken) {
  var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

  var matches = idTokenPartsRegex.exec(jwtToken);
  if (!matches || matches.length < 4) {
    this._log.warn('The returned id_token is not parseable.');
    return;
  }

  var crackedToken = {
    header : matches[1],
    JWSPayload : matches[2],
    JWSSig : matches[3]
  };

  return crackedToken;
};

/**
 * Finds the value that should be used as the userId value.
 * @param {object} idToken The id token that parsed.
 * @returns {object} An object with a userId field and maybe a userIdIsDisplayable field.
 */
OAuth2Client.prototype._getUserId = function(idToken) {
  var userId;
  var isDisplayable;

  if (idToken.upn) {
    userId = idToken.upn;
    isDisplayable = true;
  } else if (idToken.email) {
    userId = idToken.email;
    isDisplayable = true;
  } else if (idToken.subject) {
    userId = idToken.subject;
  }

  if (!userId) {
    // generate a random GUID.
    userId = uuid.v4();
  }

  var userIdVals = {};
  userIdVals[IdTokenFields.USER_ID] = userId;
  if (isDisplayable) {
    userIdVals[IdTokenFields.IS_USER_ID_DISPLAYABLE] = true;
  }

  return userIdVals;
};

function mapFields(inObj, outObj, map) {
  for (var key in inObj) {
    if (map[key]) {
      var mappedKey = map[key];
      outObj[mappedKey] = inObj[key];
    }
  }
}

/**
 * Given a decoded id token off the wire, this function extracts the values that
 * ADAL commonly returns to callers and translates the names to more user
 * friendly names.
 * @param  {Object} idToken A decoded id token.
 * @return {Object}         The set of extracted values with their new names.
 */
OAuth2Client.prototype._extractIdTokenValues = function(idToken) {
  var extractedValues = {};
  _.extend(extractedValues, this._getUserId(idToken));

  mapFields(idToken, extractedValues, IdTokenMap);

  return extractedValues;
};

/**
 * Parses the value of the id_token OAuth 2 Reponse.
 * @param  {string} encodedIdToken An unencrypted JWT token.
 * @return {object}                 returns the decoded id_token or undefined.
 */
OAuth2Client.prototype._parseIdToken = function(encodedIdToken) {
  var crackedToken = this._crackJwt(encodedIdToken);
  if (!crackedToken) {
    return;
  }

  var idToken;
  try {
    var base64IdToken = crackedToken.JWSPayload;
    var base64Decoded = util.base64DecodeStringUrlSafe(base64IdToken);
    if (!base64Decoded) {
      this._log.warn('The returned id_token could not be base64 url safe decoded.');
      return;
    }

    idToken = JSON.parse(base64Decoded);
  } catch(err) {
    this._log.warn('The returned id_token could not be decoded: ' + err.stack);
    return;
  }

  return this._extractIdTokenValues(idToken);
};

/**
 * Validates the response returned from an OAuth 2.0 token request.
 * @private
 * @param  {string} body  The response as a string encoded JSON object.
 * @return {object}       The parsed response.
 */
OAuth2Client.prototype._validateTokenResponse = function(body) {
  var wireResponse;
  var tokenResponse = {};

  try {
    wireResponse = JSON.parse(body);
  } catch(e) {
    throw new Error('The token response returned from the server is unparseable as JSON');
  }

  var intKeys = [
    OAuth2ResponseParameters.EXPIRES_ON,
    OAuth2ResponseParameters.EXPIRES_IN,
    OAuth2ResponseParameters.CREATED_ON
  ];

  this._parseOptionalInts(wireResponse, intKeys);

  if (wireResponse[OAuth2ResponseParameters.EXPIRES_IN]) {
    var expiresIn = wireResponse[OAuth2ResponseParameters.EXPIRES_IN];
    var now = new Date();
    wireResponse[OAuth2ResponseParameters.EXPIRES_ON] = now.add( { seconds : expiresIn });
  }

  if (wireResponse[OAuth2ResponseParameters.CREATED_ON]) {
    var tempDate = new Date();
    var createdOn = wireResponse[OAuth2ResponseParameters.CREATED_ON];
    tempDate.setTime(createdOn);
    wireResponse[OAuth2ResponseParameters.CREATED_ON] = tempDate;
  }

  if (!wireResponse[OAuth2ResponseParameters.TOKEN_TYPE]) {
    throw this._log.createError('wireResponse is missing token_type');
  }
  if (!wireResponse[OAuth2ResponseParameters.ACCESS_TOKEN]) {
    throw this._log.createError('wireResponse missing access_token');
  }

  mapFields(wireResponse, tokenResponse, TOKEN_RESPONSE_MAP);

  if (wireResponse[OAuth2ResponseParameters.ID_TOKEN]) {
    var idToken = this._parseIdToken(wireResponse[OAuth2ResponseParameters.ID_TOKEN]);
    if (idToken) {
      _.extend(tokenResponse, idToken);
    }
  }

  return tokenResponse;
};

/**
 * @private
 * @param {object}                   response    An http response object.
 * @param {string}                   body        The body of a http token response.
 * @param {OAuth2Client.GetTokenCallback}    callback    A call back function.  The body parameter is the body parameter passed
 *                                               into this function.
 */
OAuth2Client.prototype._handleGetTokenResponse = function(response, body, callback) {
  var tokenResponse;
  try {
    tokenResponse = this._validateTokenResponse(body);
  } catch (e) {
    this._log.error('Error validating get token response', e);
    callback(e);
    return;
  }
  callback(null, tokenResponse);
};

/**
 * @callback GetTokenCallback
 * @memberOf OAuth2Client
 * @param {Error} [error] In case of an error this will hold the associated Error object.
 * @param {TokenResponse} tokenResponse Contains the parsed result of a get token request.
 */

/**
* @param {object}                           oauthParameters     An object whose keys come from
*                                                               Constants.OAuth2.Parameters
* @param {OAuth2Client.GetTokenCallback}   callback            The callback function.
*/
OAuth2Client.prototype.getToken = function (oauthParameters, callback) {
  var self = this;
  var tokenUrl = self._createTokenUrl();

  var urlEncodedTokenRequestForm = querystring.stringify(oauthParameters);

  var postOptions = util.createRequestOptions(
    this,
    {
      'url' : tokenUrl,
      body : urlEncodedTokenRequestForm,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      followRedirect : false,
      encoding : 'utf8'
    }
  );

  request.post(postOptions, util.createRequestHandler('Get Token', this._log, callback,
    function (response, body) {
      self._handleGetTokenResponse(response, body, callback);
    })
  );
};

module.exports = OAuth2Client;
