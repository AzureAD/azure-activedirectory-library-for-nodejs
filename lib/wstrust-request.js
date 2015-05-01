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

var request = require('request');
var uuid = require('node-uuid');

var Logger = require('./log').Logger;
var util = require('./util');
var WSTrustResponse = require('./wstrust-response');

var USERNAME_PLACEHOLDER = '{UsernamePlaceHolder}';
var PASSWORD_PLACEHOLDER = '{PasswordPlaceHolder}';

/**
 * Creates a new instance of WSTrustRequest
 * @constructor
 * @private
 * @param {object} callContext Contains any context information that applies to the request.
 * @param {string}     wstrustEndpointUrl    An STS WS-Trust soap endpoint.
 * @param {string}     appliesTo             A URI that identifies a service for which the a token is to be obtained.
 */
function WSTrustRequest(callContext, wstrustEndpointUrl, appliesTo) {
  this._log = new Logger('WSTrustRequest', callContext._logContext);
  this._callContext = callContext;
  this._wstrustEndpointUrl = wstrustEndpointUrl;
  this._appliesTo = appliesTo;
}

/**
* Given a Date object adds the minutes parameter and returns a new Date object.
* @private
* @static
* @memberOf WSTrustRequest
* @param {Date}     date      A Date object.
* @param {Number}   minutes   The number of minutes to add to the date parameter.
* @returns {Date}             Returns a Date object.
*/
function _datePlusMinutes(date, minutes) {
  var minutesInMilliSeconds = minutes * 60 * 1000;
  var epochTime = date.getTime() + minutesInMilliSeconds;
  return new Date(epochTime);
}

/**
 * Builds the soap security header for the RST message.
 * @private
 * @param {string}   username  A username
 * @param {string}   password  The passowrd that corresponds to the username parameter.
 * @returns {string}           A string that contains the soap security header.
 */
WSTrustRequest.prototype._buildSecurityHeader = function() {
  var timeNow = new Date();
  var expireTime =
_datePlusMinutes(timeNow, 10);
  var timeNowString = timeNow.toISOString();
  var expireTimeString = expireTime.toISOString();

  var securityHeaderXml =
  '<wsse:Security s:mustUnderstand=\'1\' xmlns:wsse=\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\'>\
    <wsu:Timestamp wsu:Id=\'_0\'>\
      <wsu:Created>' + timeNowString + '</wsu:Created>\
      <wsu:Expires>' + expireTimeString + '</wsu:Expires>\
    </wsu:Timestamp>\
    <wsse:UsernameToken wsu:Id=\'ADALUsernameToken\'>\
      <wsse:Username>' + USERNAME_PLACEHOLDER + '</wsse:Username>\
      <wsse:Password>' + PASSWORD_PLACEHOLDER + '</wsse:Password>\
    </wsse:UsernameToken>\
  </wsse:Security>';

  return securityHeaderXml;
};

/**
 * Replaces the placeholders in the RST template with the actual username and password values.
 * @private
 * @param {string}   RSTTemplate  An RST with placeholders for username and password.
 * @param {string}   username     A username
 * @param {string}   password     The passowrd that corresponds to the username parameter.
 * @returns {string}              A string containing a complete RST soap message.
 */

WSTrustRequest.prototype._populateRSTUsernamePassword = function(RSTTemplate, username, password) {
  var RST = RSTTemplate.replace(USERNAME_PLACEHOLDER, username).replace(PASSWORD_PLACEHOLDER, password);
  return RST;
};

/**
 * Builds a WS-Trust RequestSecurityToken (RST) message using username password authentication.
 * @private
 * @param {string}   username  A username
 * @param {string}   password  The passowrd that corresponds to the username parameter.
 * @returns {string}           A string containing a complete RST soap message.
 */
WSTrustRequest.prototype._buildRST = function(username, password) {
  var messageID = uuid.v4();

  // Create a template RST with placeholders for the username and password so the
  // the RST can be logged without the sensitive information.
  var RSTTemplate =
    '<s:Envelope xmlns:s=\'http://www.w3.org/2003/05/soap-envelope\' xmlns:wsa=\'http://www.w3.org/2005/08/addressing\' xmlns:wsu=\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\'>\
      <s:Header>\
        <wsa:Action s:mustUnderstand=\'1\'>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>\
        <wsa:messageID>urn:uuid:' + messageID + '</wsa:messageID>\
        <wsa:ReplyTo>\
          <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>\
        </wsa:ReplyTo>\
        <wsa:To s:mustUnderstand=\'1\'>' + this._wstrustEndpointUrl + '</wsa:To>\
        ' + this._buildSecurityHeader() + '\
      </s:Header>\
      <s:Body>\
        <wst:RequestSecurityToken xmlns:wst=\'http://docs.oasis-open.org/ws-sx/ws-trust/200512\'>\
          <wsp:AppliesTo xmlns:wsp=\'http://schemas.xmlsoap.org/ws/2004/09/policy\'>\
            <wsa:EndpointReference>\
              <wsa:Address>' + this._appliesTo + '</wsa:Address>\
            </wsa:EndpointReference>\
          </wsp:AppliesTo>\
          <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>\
          <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>\
        </wst:RequestSecurityToken>\
      </s:Body>\
    </s:Envelope>';

  this._log.verbose('Created RST: \n' + RSTTemplate);

  var RST = this._populateRSTUsernamePassword(RSTTemplate, username, password);
  return RST;
};

/**
 * Handles the processing of a RSTR
 * @private
 * @param  {string}   body
 * @param  {WSTrustRequest.AcquireTokenCallback} callback
 */
WSTrustRequest.prototype._handleRSTR = function(body, callback) {
  var err;

  var wstrustResponse = new WSTrustResponse(this._callContext, body);
  try {
    wstrustResponse.parse();
  } catch (error) {
    err = error;
  }

  callback(err, wstrustResponse);
};

/**
 * Performs a WS-Trust RequestSecurityToken request to obtain a federated token in exchange for a username password.
 * @param {string}   username  A username
 * @param {string}   password  The passowrd that corresponds to the username parameter.
 * @param {WSTrustRequest.AcquireTokenCallback} callback   Called once the federated token has been retrieved or on error.
*/
WSTrustRequest.prototype.acquireToken = function(username, password, callback) {
  var self = this;
  var RST = this._buildRST(username, password);

  var options = util.createRequestOptions(
    this,
    {
      headers : {
        'Content-Type' : 'application/soap+xml; charset=utf-8',
        'SOAPAction' : 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
      },
      body : RST
    }
  );

  this._log.verbose('Sending RST to: ' + this._wstrustEndpointUrl);

  request.post(this._wstrustEndpointUrl, options, util.createRequestHandler('WS-Trust RST', this._log, callback,
    function(response, body) {
      self._handleRSTR(body, callback);
    }
  ));
};

/**
* @callback AcquireTokenCallback
* @memberOf WSTrustRequest
* @param {Error} err   Contains an error object if acquireToken fails.
* @param {WSTrustResponse} A successful response to the RST.
*/

module.exports = WSTrustRequest;
