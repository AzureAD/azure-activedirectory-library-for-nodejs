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

var adal = testRequire('adal');
var AuthenticationContext = adal.AuthenticationContext;

suite('device-code', function () {
    setup(function () {
        util.resetLogging();
        util.clearStaticCache();
    });

    function setupExpectedTokenRequestResponse(httpCode, returnDoc, authorityEndpoint) {
        var authEndpoint = util.getNockAuthorityHost(authorityEndpoint);
        
        var queryParameters = {};
        queryParameters['grant_type'] = 'device_code';
        queryParameters['client_id'] = cp.clientId;
        queryParameters['resource'] = cp.resource;
        queryParameters['code'] = cp.deviceCode;
        
        var query = querystring.stringify(queryParameters);
        
        var tokenRequest = nock(authEndpoint)
                                .filteringRequestBody(function (body) {
                                    return util.filterQueryString(query, body);
                                 })
                                .post(cp.tokenUrlPath, query)
                                .reply(httpCode, returnDoc);
        
        util.matchStandardRequestHeaders(tokenRequest);
        
        return tokenRequest;
    }
    
    test('happy-path-successOnFirstRequest', function (done) {
        var response = util.createResponse();
        var tokenRequest = setupExpectedTokenRequestResponse(200, response.wireResponse);
        
        var userCodeInfo = { device_code: cp.deviceCode, interval: 1, expires_in: 1 };
        var context = new AuthenticationContext(cp.authUrl);
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err, tokenResponse) {
            assert(!err, 'Receive unexpected error');
            tokenRequest.done();
            done(err);
        });
    });

    function setupExpectedTokenRequestResponseWithAuthPending(returnDoc, authorityEndpoint) {
       var authEndpoint = util.getNockAuthorityHost();

       var queryParameter = {};
       queryParameter['grant_type'] = 'device_code';
       queryParameter['client_id'] = cp.clientId;
       queryParameter['resource'] = cp.resource;
       queryParameter['code'] = cp.deviceCode;
       var query = querystring.stringify(queryParameter);
       
       var authPendingResponse = { error: 'authorization_pending'};

       var tokenRequest = nock(authEndpoint)
                          .filteringRequestBody(function(body) {
                             return util.filterQueryString(query, body);
                          })
                          .post(cp.tokenUrlPath, query)
                          .reply(400, authPendingResponse)
                          .post(cp.tokenUrlPath, query)
                          .reply(200, returnDoc);
       
       util.matchStandardRequestHeaders(tokenRequest);

       return tokenRequest;
    }

    test('happy-path-pendingOnFirstRequest', function (done) {
        var response = util.createResponse();
        var tokenRequest = setupExpectedTokenRequestResponseWithAuthPending(response.wireResponse);
        
        var userCodeInfo = { device_code: cp.deviceCode, interval: 1, expires_in: 200 };
        var context = new AuthenticationContext(cp.authUrl);
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err, tokenResponse) {
           if (!err) {
              assert(util.isMatchTokenResponse(response.cachedResponse, tokenResponse), 'The response did not match what was expected');
              tokenRequest.done();
           }
           done(err);
        });
    });

    test('happy-path-cancelRequest', function (done) {
        nock.cleanAll();
        var response = util.createResponse();
        var tokenRequest = setupExpectedTokenRequestResponseWithAuthPending(response.wireResponse);
        
        var userCodeInfo = { device_code: cp.deviceCode, interval: 1, expires_in: 200 };
        var context = new AuthenticationContext(cp.authUrl);

        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err, tokenResponse) {
           assert(err, 'Did not receive expected error');
           assert(err.message === 'Polling_Request_Cancelled');
           done();
        });

        context.cancelRequestToGetTokenWithDeviceCode(userCodeInfo, function(err) {
           assert(!err, 'Receive unexpected error.')
        });
    });
    
    test('bad-argument', function (done) {
        nock.cleanAll();
        var context = new AuthenticationContext(cp.authUrl);

        var userCodeInfo = { interval: 5, expires_in: 1000};
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo is missing device_code');
        });

        userCodeInfo = { device_code: 'test_device_code', expires_in: 1000 };
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo is missing interval');
        });

        userCodeInfo = { device_code: 'test_device_code', interval: 5 };
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo is missing expires_in');
        });

        // test if usercodeInfo is null
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, null, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo parameter is required');
        });

        userCodeInfo = { device_code: 'test_device_code', interval: 5, expires_in: 1000 };
        try {
            context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo);
        } catch (e) {
            assert(e, 'Did not receive expected error. ');
            assert(e.message === 'acquireToken requires a function callback parameter.', 'Unexpected error message returned.');
        }

        userCodeInfo = { device_code: 'test_device_code', interval: 0, expires_in: 1000 };
        context.acquireTokenWithDeviceCode(cp.resource, cp.clientId, userCodeInfo, function (err) {
          assert(err, 'Did not receive expected error.');
          assert(err.message === 'invalid refresh interval');
        });
        
        done();
    });

    test('bad-argument-cancel-request', function (done) {
       var context = new AuthenticationContext(cp.authUrl);

        var userCodeInfo = { interval: 5, expires_in: 1000 };
        context.cancelRequestToGetTokenWithDeviceCode(userCodeInfo, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo is missing device_code');
        });

        // test if usercodeInfo is null
        context.cancelRequestToGetTokenWithDeviceCode(null, function (err) {
            assert(err, 'Did not receive expected argument error');
            assert(err.message === 'The userCodeInfo parameter is required');
        });

        userCodeInfo = { device_code: 'test_device_code', interval: 5, expires_in: 1000 };
        try {
            context.cancelRequestToGetTokenWithDeviceCode(userCodeInfo);
        } catch (e) {
            assert(e, 'Did not receive expected error. ');
            assert(e.message === 'acquireToken requires a function callback parameter.', 'Unexpected error message returned.');
        }

        userCodeInfo = { device_code: cp.deviceCode, interval: 1, expires_in: 200 };
        context.cancelRequestToGetTokenWithDeviceCode(userCodeInfo, function (err) {
            assert(err, 'Did not receive expected error. ');
            assert(err.message === 'No acquireTokenWithDeviceCodeRequest existed to be cancelled', 'Unexpected error message returned.');
        })
        
        done();
    });
});