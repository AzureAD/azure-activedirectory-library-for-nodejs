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
var nock = require('nock');
var querystring = require('querystring');

var util = require('./util/util');
var testRequire = util.testRequire;
var cp = util.commonParameters;

var adal = testRequire('../lib/adal');
var AuthenticationContext = adal.AuthenticationContext;

/**
 * Tests AuthenticationContext.acquireTokenWithAuthorizationCode
 */
suite('authorization-code', function() {
  var authorizationCode = '1234870909';
  var redirectUri = 'app_bundle:foo.bar.baz';
  var policy = 'testing_policy';
  
  function setupQueryParameters(withPolicy){
    var queryParameters = {};
    queryParameters['grant_type'] = 'authorization_code';
    queryParameters['code'] = authorizationCode;
    queryParameters['client_id'] = cp.clientId;
    queryParameters['client_secret'] = cp.clientSecret;
    queryParameters['redirect_uri'] = redirectUri;
    queryParameters['scope'] = util.parseScope(cp.scope);
    
    if (withPolicy){
       queryParameters['p'] = policy; 
    }
  }

  function setupExpectedAuthCodeTokenRequestResponse(queryParameters, httpCode, returnDoc, authorityEndpoint) {
    var authEndpoint = util.getNockAuthorityHost(authorityEndpoint);

    var queryParameters = {};
    queryParameters['grant_type'] = 'authorization_code';
    queryParameters['code'] = authorizationCode;
    queryParameters['client_id'] = cp.clientId;
    queryParameters['client_secret'] = cp.clientSecret;
    queryParameters['redirect_uri'] = redirectUri;
    queryParameters['scope'] = util.parseScope(cp.scope);
    var query = querystring.stringify(queryParameters);

    var tokenRequest = nock(authEndpoint)
                            .filteringRequestBody(function(body) {
                              return util.filterQueryString(query, body);
                            })
                           .post(cp.tokenUrlPath, query)
                           .reply(httpCode, returnDoc);

    util.matchStandardRequestHeaders(tokenRequest);

    return tokenRequest;
  }

  test('happy-path-without-policy', function(done) {
    var response = util.createResponse();
    var tokenRequest = setupExpectedAuthCodeTokenRequestResponse(setupQueryParameters(false), 200, response.wireResponse);

    var context = new AuthenticationContext(cp.authUrl);
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, response.scope, cp.clientId, cp.clientSecret, null, function (err, tokenResponse) {
      if (!err) {
        assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected');
        tokenRequest.done();
      }
      done(err);
    });
  });

  test('happy-path-with-policy', function(done) {
    var response = util.createResponse();
    var tokenRequest = setupExpectedAuthCodeTokenRequestResponse(setupQueryParameters(true), 200, response.wireResponse);
        
    var context = new AuthenticationContext(cp.authUrl);
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, response.scope, cp.clientId, cp.clientSecret, null, function (err, tokenResponse) {
        if (!err) {
           assert(util.isMatchTokenResponse(response.decodedResponse, tokenResponse), 'The response did not match what was expected');
           tokenRequest.done();
        }
        done(err);
     });
  });

  test('failed-http-request', function(done) {
    this.timeout(6000);
    this.slow(4000);  // This test takes longer than I would like to fail.  It probably needs a better way of producing this error.

    nock.enableNetConnect();
    var context = new AuthenticationContext('https://0.1.1.1:12/my.tenant.com');
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, cp.scope, cp.clientId, cp.clientSecret, null, function (err) {
      assert(err, 'Did not recieve expected error on failed http request.');
    });

    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, cp.scope, cp.clientId, cp.clientSecret, policy, function (err) {
       assert(err, 'Did not recieve expected error on failed http request.');
       nock.disableNetConnect();
       done();
    })
  });

  test('bad-argument', function(done) {
    var context = new AuthenticationContext(cp.authUrl);
    
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, null, cp.clientId, cp.clientSecret, null, function (err) {
      assert(err, 'Did not receive expected argument error.');
    });

    //no callback
    try{
       context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, cp.scope, cp.clientId, cp.clientSecret, null);
    } catch (e) {
       assert(e, 'Expect error returned');
       assert(e.message === 'acquireToken requires a function callback parameter.', 'Unexpected error message returned.');
    }

    // scope is null
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, null, cp.clientId, cp.clientSecret, null, function (err) {
       assert(err, 'Did not receive expected argument error.');
       assert(err.message === 'The scope parameter is required.');
    })

    // scope is not array
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, 'scope', cp.clientId, cp.clientSecret, null, function (err) {
       assert(err, 'Did not receive expected argument error.');
       assert(err.message === 'The scope parameter must be of type Array.', 'Unexpected error message returned.');
    })

    // scope contains non-string argument
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, ['scope', 1], cp.clientId, cp.clientSecret, null, function (err) {
       assert(err, 'Did not receive expected argument error.');
       assert(err.message === 'The scope parameter must be consisted of an array of String');
    })

    // clientId is null
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, cp.scope, null, cp.clientSecret, null, function (err) {
        assert(err, 'Did not receive expected argument error.');
        assert(err.message === 'The clientId parameter is required.');
    })

    // clientId is not string
    context.acquireTokenWithAuthorizationCode(authorizationCode, redirectUri, cp.scope, 2, cp.clientSecret, null, function (err) {
        assert(err, 'Did not receive expected argument error.');
        assert(err.message === 'The clientId parameter must be of type String.');
    });

    done();
  });
});
