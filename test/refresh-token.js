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


// Run
//   npm test
// from root of the repo

var assert = require('assert');
var util = require('./util/util');

var cp = util.commonParameters;
var testRequire = util.testRequire;

var adal = testRequire('../lib/adal');
var AuthenticationContext = adal.AuthenticationContext;


suite('refresh-token', function() {
  test('happy-path-no-scope-and-clientsecret', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, null, null, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
      }
      done(err);
    });
  });

  test('happy-path-with-scope', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, response.scope);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, null, cp.scope, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse))  ;
      }
      done(err);
    });
  });

  test('happy-path-with-scope-and-policy-and-redirecturi', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var policy = 'testing_policy';
    var redirect_uri = 'redirect_uri:';
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, response.scope, null, policy, redirect_uri);
        
    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, null, cp.scope, policy, redirect_uri, function (err, tokenResponse) {
    if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
    }
    done(err);
    });
  });

  test('happy-path-no-scope-client-secret', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, null, cp.clientSecret);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, cp.clientSecret, null, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
      }
      done(err);
    });
  });

  test('happy-path-with-scope-client-secret', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, response.scope, cp.clientSecret);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, cp.clientSecret, cp.scope, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse))  ;
      }
      done(err);
    });
  });
    
  test('happy-path-policy-empty', function (done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;

    var redirect_uri = 'redirect_uri:';
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, response.scope, cp.clientSecret, '', redirect_uri);
        
    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, cp.clientSecret, cp.scope, '', redirect_uri, function (err, tokenResponse) {
        if (!err) {
            tokenRequest.done();
            assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
        }
        done(err);
    });
 });

  test('happy-path-no-scope-legacy', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, null, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
      }
      done(err);
    });
  });

  test('happy-path-with-scope-legacy', function(done) {
    var responseOptions = { refreshedRefresh : true };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedRefreshTokenRequestResponse(200, wireResponse, response.authority, response.scope);

    var context = new AuthenticationContext(cp.authorityTenant);
    context.acquireTokenWithRefreshToken(cp.refreshToken, cp.clientId, cp.scope, null, null, function(err, tokenResponse) {
      if (!err) {
        tokenRequest.done();
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected: ' + JSON.stringify(tokenResponse));
      }
      done(err);
    });
  });
});