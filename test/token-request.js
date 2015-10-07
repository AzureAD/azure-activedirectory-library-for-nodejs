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
/* Directive tells jshint that suite and test are globals defined by mocha */
/* global suite */
/* global test */

var assert = require('assert');
var util = require('./util/util');

var sinon = require('sinon');

var cp = util.commonParameters;
var testRequire = util.testRequire;
var adal = testRequire('adal');
var AuthenticationContext = adal.AuthenticationContext;
var TokenRequest = testRequire('token-request');

suite('token-request capture surface correct error', function () {
  
  //set up test artifacts
  var parsedIdToken = {
    'tenantId' : cp.tenant,
    'userId' : cp.username,
    '_authority': cp.authorityTenant,
    'accessToken' : 'blahblah',
    'clientId' : cp.clientId,
    'refreshToken': cp.refreshToken,
    'resource': cp.resource,
    'isMRRT' : true
  }; var cachedTokenList = [parsedIdToken];
  var testTokenCache = {
    'find': function (query, cb) { cb(null, cachedTokenList); }
  };
  var context = new AuthenticationContext(cp.authorityTenant, false, testTokenCache);
  var fakedHostname = 'some.foobar.site';
  context._authority._tokenEndpoint = 'http://' + fakedHostname;
  var callContext = { '_logContext' : {} };
  
  function verifyError(err) {
    assert(err.message.indexOf(fakedHostname) > 0);
  }
  
  //test cases
  test('when it gets more than 2 matched tokens', function (done) {
    cachedTokenList.push(cachedTokenList[0]);
    var tokenRequest = new TokenRequest(callContext, context, cp.clientId, cp.resource, null);
    tokenRequest.getTokenFromCacheWithRefresh('user@foo.com', function (err) {
      cachedTokenList.pop();
      assert(err.message === 'Error: More than one token matches the criteria. The result is ambiguous.');
      done();
    });
  });
  
  test('when token refresh failed for getTokenFromCacheWithRefresh', function (done) {
    var tokenRequest = new TokenRequest(callContext, context, cp.clientId, cp.resource, null);
    tokenRequest.getTokenFromCacheWithRefresh('user@foo.com', function (err) {
      verifyError(err);
      done();
    });
  });
  
  test('when token refresh failed for getTokenWithUsernamePassword', function (done) {
    var tokenRequest = new TokenRequest(callContext, context, cp.clientId, cp.resource, null);
    tokenRequest.getTokenWithUsernamePassword('user@foo.com', 'password', function (err) {
      verifyError(err);
      done();
    });
  });
  
  test('when token refresh failed for getTokenWithClientCredentials', function (done) {
    var tokenRequest = new TokenRequest(callContext, context, cp.clientId, cp.resource, null);
    tokenRequest.getTokenFromCacheWithRefresh('mysecret', function (err) {
      verifyError(err);
      done();
    });
  });
  
  test('when token refresh failed for getTokenWithCertificate', function (done) {
    var tokenRequest = new TokenRequest(callContext, context, cp.clientId, cp.resource, null);
    sinon.stub(tokenRequest, '_createJwt').returns({});
    tokenRequest.getTokenWithCertificate('certificate1', 'thumbprint1', function (err) {
      verifyError(err);
      tokenRequest._createJwt.restore();
      done();
    });
  });
});