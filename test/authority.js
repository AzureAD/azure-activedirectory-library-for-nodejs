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
var cp = util.commonParameters;
var testRequire = util.testRequire;

var adal = testRequire('adal');
var AuthenticationContext = adal.AuthenticationContext;
var Authority = testRequire('authority').Authority;

/**
 * Tests the Authority class and instance discovery.
 */
suite('Authority', function() {

  // use this as authority to force dynamic as opposed to static instance discovery.
  var nonHardCodedAuthority = 'https://login.doesntexist.com/' + cp.tenant;


  function setupExpectedInstanceDiscoveryRequestRetries(requestParametersList, authority) {
    var nocks = [];

    requestParametersList.forEach(function(request) {
      nocks.push(util.setupExpectedInstanceDiscoveryRequest(request.httpCode, request.authority, request.returnDoc, authority));
    });

    return nocks;
  }

  test('success-dynamic-instance-discovery', function(done) {
    var instanceDiscoveryRequest = util.setupExpectedInstanceDiscoveryRequest(
      200,
      cp.authorityHosts.global,
      {
        'tenant_discovery_endpoint' : 'http://foobar'
      },
      nonHardCodedAuthority
    );

    var responseOptions = {
      authority : nonHardCodedAuthority
    };
    var response = util.createResponse(responseOptions);
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedClientCredTokenRequestResponse(200, wireResponse, nonHardCodedAuthority);

    var context = new AuthenticationContext(nonHardCodedAuthority);
    context.acquireTokenWithClientCredentials(response.resource, cp.clientId, cp.clientSecret, function (err, tokenResponse) {
      if (!err) {
        assert(util.isMatchTokenResponse(response.cachedResponse, tokenResponse), 'The response does not match what was expected.: ' + JSON.stringify(tokenResponse));
        instanceDiscoveryRequest.done();
        tokenRequest.done();
      }
      done(err);
    });
  });

  test('http-error', function(done) {
    var expectedInstanceDiscoveryRequests = [
      {
        httpCode : 500,
        authority : cp.authorityHosts.global
        //returnDoc : null
      }
    ];

    var instanceDiscoveryRequests = setupExpectedInstanceDiscoveryRequestRetries(expectedInstanceDiscoveryRequests, nonHardCodedAuthority);

    var context = new AuthenticationContext(nonHardCodedAuthority);
    context.acquireTokenWithClientCredentials(cp.resource, cp.clientId, cp.clientSecret, function (err) {
      assert(err, 'No error was returned when one was expected.');
      assert(err.message.indexOf('500') !== -1, 'The http error was not returned');
      instanceDiscoveryRequests.forEach(function(request){
        request.done();
      });

      done();
    });
  });

  test('validation-error', function(done) {
    var expectedInstanceDiscoveryRequests = [
      {
        httpCode : 400,
        authority : cp.authorityHosts.global,
        returnDoc : { error : 'invalid_instance', 'error_description' : 'the instance was invalid' }
      }
    ];

    var instanceDiscoveryRequests = setupExpectedInstanceDiscoveryRequestRetries(expectedInstanceDiscoveryRequests, nonHardCodedAuthority);

    var context = new AuthenticationContext(nonHardCodedAuthority);
    context.acquireTokenWithClientCredentials(cp.resource, cp.clientId, cp.clientSecret, function (err) {
      assert(err, 'No error was returned when one was expected.');
      assert(err.message.indexOf('invalid_instance') !== -1, 'The server error was not returned');
      assert(err.message.indexOf('instance was invalid') !== -1, 'The server error message was not returned');
      instanceDiscoveryRequests.forEach(function(request){
        request.done();
      });

      done();
    });
  });

  test('validation-off', function(done) {
    var response = util.createResponse();
    var wireResponse = response.wireResponse;
    var tokenRequest = util.setupExpectedClientCredTokenRequestResponse(200, wireResponse, response.authority);

    var context = new AuthenticationContext(cp.authorityTenant, false);
    context.acquireTokenWithClientCredentials(response.resource, cp.clientId, cp.clientSecret, function (err, tokenResponse) {
      if (!err) {
        assert(util.isMatchTokenResponse(response.cachedResponse, tokenResponse), 'The response does not match what was expected.');
        tokenRequest.done();
      }
      done(err);
    });
  });

  test('bad-url-not-https', function(done) {
    var errorThrown;
    var context;
    try {
      context = new AuthenticationContext('http://this.is.not.https.com/mytenant.com');
    } catch(err) {
      errorThrown = err;
    }

    // This makes jshint happy that we haven't assigned a variable that is never uesd.
    context = null;

    assert(errorThrown, 'AuthenticationContext succeeded when it should have failed.');
    assert(errorThrown.message.indexOf('https') >= 0, 'Error message does not mention the need for https: ' + errorThrown.message);
    done();
  });

  test('bad-url-has-query', function(done) {
    var errorThrown;
    var context;
    try {
      context = new AuthenticationContext(cp.authorityTenant + '?this=should&not=be&here=foo');
    } catch(err) {
      errorThrown = err;
    }

    // This makes jshint happy that we haven't assigned a variable that is never uesd.
    context = null;

    assert(errorThrown, 'AuthenticationContext succeeded when it should have failed.');
    assert(errorThrown.message.indexOf('query') >= 0, 'Error message does not mention the offending query string: ' + errorThrown.message);
    done();
  });

  test('url-extra-path-elements', function(done) {
    var instanceDiscoveryRequest = util.setupExpectedInstanceDiscoveryRequest(
      200,
      cp.authorityHosts.global,
      {
        'tenant_discovery_endpoint' : 'http://foobar'
      },
      nonHardCodedAuthority
    );

    // add extra path and query string to end of the authority.  These should be stripped
    // out before the url is sent to instance discovery.
    var authorityUrl = nonHardCodedAuthority + '/extra/path';
    var authority = new Authority(authorityUrl, true);
    var obj = util.createEmptyADALObject();
    authority.validate(obj._callContext, function(err) {
      if (err) {
        assert(!err, 'Recieved unexpected error: ' + err.stack);
      }
      instanceDiscoveryRequest.done();
      done();
    });
  });
});
