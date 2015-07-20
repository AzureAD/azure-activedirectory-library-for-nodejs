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


var _ = require('underscore');
var async = require('async');

var util = require('./util/util');
var cp = util.commonParameters;
var testRequire = util.testRequire;

var assert = require('assert');

var MemoryCache = testRequire('../lib/memory-cache');
var CacheDriver = testRequire('../lib/cache-driver');

suite('CacheDriver', function() {

  function unexpectedRefreshFunction() {
    assert(false, 'Unexpected attempt to refresh a token.');
  }

  function assertEntriesEqual(expected, received, message) {
    if (!_.isEqual(expected, received)) {
      util.findDiffs(expected, received);
      console.log('Expected:');
      console.log(expected);
      console.log('Recieved');
      console.log(received);
      assert(false, message);
    }
  }

  /*
   * Compares two lists of cache entries.  The lists will be sorted before comparison and the comparison will
   * take in to account the different ways that MRRT is indicated when a cache entry is submitted to the cache
   * and once it is in the cache.
   */
  function compareInputAndCache(input, cache, numMRRTTokens, mrrtRefreshToken) {
    var foundNumMRRTTokens = 0;
    var cacheEntries = cache._entries;
    var authority = cp.authorityTenant;
    var userId = cp.username;

    assert(input.length === cacheEntries.length, 'Input responses and cache entries lengths are not the same: ' + input.length + ',' + cacheEntries.length);

    input = _.sortBy(input, 'accessToken');
    cacheEntries = _.sortBy(cacheEntries, 'accessToken');

    for (var j = 0; j < cacheEntries.length; j++) {
      var expected = _.clone(input[j]);
      var received = _.clone(cacheEntries[j]);

      if (received.isMRRT) {
        foundNumMRRTTokens++;
        if (received._authority === authority && received.userId === userId) {
          // Everything should match except the refresh token.  We will check that below.
          delete expected['refreshToken'];
          delete received['refreshToken'];
        }
      }
      assertEntriesEqual(expected, received, 'Found a modified entry number ' + j);
    }

    if (numMRRTTokens) {
      assert(numMRRTTokens === foundNumMRRTTokens, 'Found wrong number of MRRT tokens in the cache: ' + numMRRTTokens + ',' + foundNumMRRTTokens);

      // Ensure that when the last refresh token was added that all mrrt refresh tokens were updated to contain that same
      // refresh token.
      for (var i = 0; i < cacheEntries[i].length; i++) {
        if (cacheEntries[i].isMRRT) {
          assert(cacheEntries[i]['refreshToken'] === mrrtRefreshToken, 'One of the responses refresh token was not correctly updated: ' + i);
        }
      }
    }
  }


  test('add-entry-without-policy', function(done) {
    var fakeTokenRequest = util.createEmptyADALObject();

    var response = util.createResponse();
    var expectedResponse = response.cachedResponse;

    var memCache = new MemoryCache();
    var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response.authority, response.scope, response.clientId, null, memCache, unexpectedRefreshFunction);

    cacheDriver.add(response.decodedResponse, function(err) {
      var stack = err ? err.stack : null;
      assert(!err, 'Recieved unexpected error: ' + stack);
      var length = memCache._entries.length;
      assert(length === 1, 'Cache after test has does not have the correct number of entries ' + length + ': ' + memCache._entries);
      assertEntriesEqual(expectedResponse, memCache._entries[0], 'The saved cache entry has been modified');
      done();
    });
  });

  test('add-entry-with-policy', function(done) {
     var fakeTokenRequest = util.createEmptyADALObject();
            
     var options = {};
     options.policy = cp.policy;
     var response = util.createResponse(options);
     var expectedResponse = response.cachedResponse;
            
     var memCache = new MemoryCache();
     var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response.authority, response.scope, response.clientId, cp.policy, memCache, unexpectedRefreshFunction);

     cacheDriver.add(response.decodedResponse, function(err) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);
        var length = memCache._entries.length;
        assert(length === 1, 'Cache after test has does not have the correct number of entries ' + length + ': ' + memCache._entries);
        assertEntriesEqual(expectedResponse, memCache._entries[0], 'The saved cache entry has been modified');
        done();
     });
  });

  test('cache-lookup-scope', function (done) {
     var fakeTokenRequest = util.createEmptyADALObject();
     var memCache = new MemoryCache();

     var response1 = util.createResponse();
     var cacheDriver1 = new CacheDriver(fakeTokenRequest._callContext, response1.authority, response1.scope, response1.clientId, cp.policy, memCache, unexpectedRefreshFunction);
     cacheDriver1.add(response1.decodedResponse, function (err) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);
     });   
     
     var scope = ['00000002-0000-0000-c000-000000000000/openid'];
     var query = {
       clientId : cp.clientId, 
       scope : scope
     }

     var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response1.authority, response1.scope, response1.clientId, cp.policy, memCache, unexpectedRefreshFunction);
     cacheDriver.find(query, function(err, entry) {
        assert(!err, 'Unexpected error received');
        assert(entry, 'Expected a matching entry, but none was returned.');
     });

     scope = ['00000002-0000-0000-c000-000000000000/openid', '00000002-0000-0000-c000-000000000000/mail.read', '00000002-0000-0000-c000-000000000000/mail.Write'];
     query = {
        clientId : cp.clientId, 
        scope : scope
     }
     var cacheDriver2 = new CacheDriver(fakeTokenRequest._callContext, response1.authority, scope, response1.clientId, cp.policy, memCache, unexpectedRefreshFunction);
     cacheDriver2.find(query, function(err, entry) {
        assert(!err, 'Receive unexpected error.')
        assert(!entry, 'No matching record should be returned.');
     });
     done();
  });
    
  test('manage-cache', function (done) {
     var fakeTokenRequest = util.createEmptyADALObject();
     var memCache = new MemoryCache();

     var options = {};
     options.policy = cp.policy;
     var response = util.createResponse(options);

     var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response.authority, response.scope, response.clientId, cp.policy, memCache, unexpectedRefreshFunction);
     cacheDriver.add(response.decodedResponse, function(err) {
        assert(!err, 'Receive unexpected error.');
     });

     var scope = ['00000002-0000-0000-c000-000000000000/openid', '00000002-0000-0000-c000-000000000000/mail.read', '00000002-0000-0000-c000-000000000000/mail.Write'];
     options.scope = scope;
     var response2 = util.createResponse(options);
     var cacheDriver2 = new CacheDriver(fakeTokenRequest._callContext, response.authority, scope, response.clientId, cp.policy, memCache, unexpectedRefreshFunction);
     cacheDriver2.manageCache(response2.decodedResponse, function(err) {
        assert(!err);
     })

     var query = {
        clientId : cp.clientId, 
        policy : cp.policy
     }

     cacheDriver2.find(query, function(err, entry) {
        assert(!err, 'Receives unexpected error.');
        assert(entry, 'Expected a matching entry, but none was returned');
        assert.equal(entry.scope, util.parseScope(scope), 'scope is not as expected');
     });

     done();
  });

  test('cache-lookup-policy', function (done) {
    var fakeTokenRequest = util.createEmptyADALObject();
    var memCache = new MemoryCache();

    // insert one with policy
    var options = {};
    options.policy = cp.policy;
    var response1 = util.createResponse(options);
    var cacheDriver1 = new CacheDriver(fakeTokenRequest._callContext, response1.authority, response1.scope, response1.clientId, cp.policy, memCache, unexpectedRefreshFunction);
    cacheDriver1.add(response1.decodedResponse, function(err) {
       var stack = err ? err.stack : null;
       assert(!err, 'Received unexpected error: ' + stack);
    });   

    // create another entry without policy. 
    var response2 = util.createResponse();
    var cacheDriver2 = new CacheDriver(fakeTokenRequest._callContext, response2.authority, response2.scope, response2.clientId, null, memCache, unexpectedRefreshFunction);
    cacheDriver2.add(response2.decodedResponse, function(err) {
       var stack = err ? err.stack : null;
       assert(!err, 'Received unexpected error: ' + stack);
    });

    // construct the query for lookup
    var query = {
        clientId : cp.clientId, 
        policy : cp.policy, 
        scope : cp.scope
    };

    // test cache look up with policy
    var lookupCacheDriver = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, cp.scope, cp.clientId, cp.policy, memCache, unexpectedRefreshFunction);
    lookupCacheDriver.find(query, function(err, entry) {
        assert (!err, 'Unexpected error received');
        assert(entry, 'Expected a matching entry, but none was returned.');  
    });

    // test cache look up with policy
    query = {
       clientId : cp.clientId, 
       scope : cp.scope
    }; 
    var lookupCacheDriver2 = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, cp.scope, cp.clientId, null, memCache, unexpectedRefreshFunction);
    lookupCacheDriver2.find(query, function (err, entry) {
       assert(err, 'Expecting error for the cache lookup');
       assert(err.message === 'More than one token matches the criteria.  The result is ambiguous.', 'unexpected error message received');
    }); 

    //test cache look up with policy but a subset scope, expecte one entry to be found
    var scope = ['00000002-0000-0000-c000-000000000000/openid'];
    query = {
       clientId : cp.clientId, 
       policy : cp.policy, 
       scope : scope
    };
    var lookupCacheDriver3 = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, scope, cp.clientId, cp.policy, memCache, unexpectedRefreshFunction);
    lookupCacheDriver3.find(query, function (err, entry) {
        assert(!err, 'Unexpected error received');
        assert(entry, 'Expected a matching entry, but none was returned.');  
    });

    // test cache look up with a subset scope but not policy, expect error returned. 
    query = {
       clientId : cp.clientId, 
       scope : scope
    }
    var lookupCacheDriver4 = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, scope, cp.clientId, null, memCache, unexpectedRefreshFunction);
    lookupCacheDriver4.find(query, function (err, entry) {
        assert(err, 'Expecting error for the cache lookup');
        assert(err.message === 'More than one token matches the criteria.  The result is ambiguous.', 'unexpected error message received');
    });

    done();
  });

  test('add-entry-no-cache', function(done) {
    var fakeTokenRequest = util.createEmptyADALObject();

    var response = util.createResponse();

    var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response.authority, response.scope, cp.clientId, null, null, unexpectedRefreshFunction);

    cacheDriver.add(response.decodedResponse, function(err) {
      var stack = err ? err.stack : null;
      assert(!err, 'Recieved unexpected error: ' + stack);
      done();
    });
  });

  test('add-entry-single-mrrt', function(done) {
    var fakeTokenRequest = util.createEmptyADALObject();

    var responseOptions = { mrrt : true };
    var response = util.createResponse(responseOptions);
    var expectedResponse = response.cachedResponse;
    var scope = response.scope;

    var memCache = new MemoryCache();
    var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, response.authority, scope, cp.clientId, null, memCache, unexpectedRefreshFunction);

    cacheDriver.add(response.decodedResponse, function(err) {
      var stack = err ? err.stack : null;
      assert(!err, 'Recieved unexpected error: ' + stack);
      var length = memCache._entries.length;
      assert(length === 1, 'Cache after test has does not have the correct number of entrie ' + length + ': ' + memCache._entries);
      assertEntriesEqual(expectedResponse, memCache._entries[0], 'The saved cache entry has been modified');
      done();
    });
  });

  /**
   * Creates a new CacheDriver with a MemoryCache and fills it with test entries.
   * @param  {int}   numEntries The total number of entries that should be in the cache
   * @param  {int}   numMrrt    The number of tokens in the cache that should be mrrt tokens.  This number must
   *                            be smaller than numEntries.
   * @param  {Function} callback   returns an object with the CacheDriver etc...
   */
  function fillCache(numEntries, numMrrt, addExpired, policy, callback) {
    var fakeTokenRequest = util.createEmptyADALObject();

    var memCache = new MemoryCache();
    var authority = cp.authorityTenant;

    var responses = [];
    var divisor = Math.floor(numEntries / numMrrt);
    var finalMrrt;
    var expiredEntry;
    for (var i = 0; i < numEntries; i++) {
      var responseOptions = { authority : cp.authorityTenant};
      if (numMrrt && ((i + 1) % divisor) === 0) {
        responseOptions.mrrt = true;
      } else if (addExpired) {
        responseOptions.expired = expiredEntry ? false : true;
      }
      var newResponse = util.createResponse(responseOptions, i);
      finalMrrt = responseOptions.mrrt ? newResponse.refreshToken : finalMrrt;
      expiredEntry = responseOptions.expired ? newResponse : expiredEntry;
      responses.push(newResponse);
    }

    var count = 0;
    var finalRefreshToken;
    async.whilst(
      function() { return count < numEntries; },
      function(callback) {
        var scope = responses[count].scope;
        var clientId = responses[count].clientId;
        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, authority, scope, clientId, null, memCache, unexpectedRefreshFunction);
        var responseToAdd = _.clone(responses[count].decodedResponse);
        cacheDriver.add(responseToAdd, function(err) {
          count++;
          process.nextTick(function() {
            callback(err);
            return;
          });
        });
      },
      function(err) {
        var cachedResponses = [];
        for (var j = 0; j < responses.length; j++) {
          cachedResponses.push(responses[j].cachedResponse);
        }

        var testValues = {
          cachedResponses : cachedResponses,
          memCache : memCache,
          finalMrrt : finalMrrt,
          fakeTokenRequest : fakeTokenRequest,
          authority : authority,
          expiredEntry : expiredEntry
        };
        callback(err, testValues, finalRefreshToken);
      }
    );
  }

  test('add-multiple-entries-ensure-authority-respected', function(done) {
    var numMRRTTokens = 6;
    fillCache(20, numMRRTTokens, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens);

        var otherAuthority = 'someOtherAuthority';
        var responseOptions = { authority : otherAuthority, mrrt : true, scope : responses[0].scope };
        var differentAuthorityResponse = util.createResponse(responseOptions);
        delete responseOptions.authority;
        var extraMRRTResponse = util.createResponse(responseOptions, 21);
        responses.push(extraMRRTResponse.cachedResponse);
        responses.push(differentAuthorityResponse.cachedResponse);
        numMRRTTokens += 2;

        // order is important here.  We want to ensure that when we add the second MRRT it has only updated
        // the refresh token of the entries with the same authority.
        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, otherAuthority, differentAuthorityResponse.scope, differentAuthorityResponse.clientId, null, memCache, unexpectedRefreshFunction);
        cacheDriver.add(differentAuthorityResponse.decodedResponse, function(err) {
          assert(!err, 'Unexpected err adding entry with different authority.');

          var cacheDriver2 = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, extraMRRTResponse.scope, extraMRRTResponse.clientId, null, memCache, unexpectedRefreshFunction);
          cacheDriver2.add(extraMRRTResponse.decodedResponse, function(err2) {
            assert(!err2, 'Unexpected error adding second entry with previous authority.');
            compareInputAndCache(responses, memCache, numMRRTTokens);

            // ensure that we only find the mrrt with the different authority.
            cacheDriver.find( { scope : differentAuthorityResponse.scope}, function(err3, entry) {
              assert(!err3, 'Unexpected error returned from find.');
              assertEntriesEqual(differentAuthorityResponse.cachedResponse, entry, 'Queried entry did not match expected indicating authority was not respected');
            });
            done();
          });
        });
      }
    });
  });

  test('add-multiple-entries-find-non-mrrt', function(done) {
    var numMRRTTokens = 6;
    fillCache(20, numMRRTTokens, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens);

        var findResponse = _.find(responses, function(entry) { return !entry.isMRRT; });
        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, findResponse.scope.split(' '), findResponse.clientId, null, memCache, unexpectedRefreshFunction);

        cacheDriver.find({}, function(err, entry) {
          if (!err) {
            assert(entry, 'Find did not return any entry');
            assertEntriesEqual(findResponse, entry, 'Queried entry did not match expected: ' + JSON.stringify(entry));
          }
          done(err);
          return;
        });
      } else {
        done(err);
        return;
      }
    });
  });

  test('add-multiple-entries-mrrt', function(done) {
    var numMRRTTokens = 6;
    fillCache(19, numMRRTTokens, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var finalMrrt = testValues.finalMrrt;

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);
      }

      done();
      return;
    });
  });

  // This test is actually testing two different things.
  //  1. When a new MRRT is added to the cache only MRRT
  //     tokens with the same userId are updated.
  //  2. Check that url safe base64 decoding is happening
  //     correctly.
  test('add-multiple-entries-mrrt-different-users--url-safe-id_token', function(done) {
    var numMRRTTokens = 6;
    fillCache(19, numMRRTTokens, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var finalMrrt = testValues.finalMrrt;
      var fakeTokenRequest = testValues.fakeTokenRequest;

      var responseOptions = { mrrt : true, refreshedRefresh : true, urlSafeUserId : true };
      var refreshedResponse = util.createResponse(responseOptions);

      // verify that the returned response contains an id_token that will actually
      // test url safe base64 decoding.
      assert(-1 !== refreshedResponse.wireResponse['id_token'].indexOf('_'), 'No special characters in the test id_token.  ' +
        'This test is not testing one of the things it was intended to test.');

      responses.push(refreshedResponse.cachedResponse);

      var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, testValues.authority, refreshedResponse.scope, refreshedResponse.clientId, null, memCache, unexpectedRefreshFunction);
      cacheDriver.add(refreshedResponse.decodedResponse, function(err) {
        if (!err) {
          compareInputAndCache(responses, memCache, numMRRTTokens + 1, finalMrrt);
        }
        done(err);
        return;
      });
    });
  });

  test('add-multiple-entries-find-mrrt', function(done) {
    var numMRRTTokens = 6;
    fillCache(20, numMRRTTokens, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;

      var mrrtEntry = _.findWhere(memCache._entries, { isMRRT : true });

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens);

        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, cp.authorityTenant, mrrtEntry.scope.split(','), mrrtEntry._clientId, null, memCache, unexpectedRefreshFunction);
        cacheDriver.find({}, function(err, entry) {
          if (!err) {
            assert(entry, 'Find did not return any entry');
            assertEntriesEqual(mrrtEntry, entry, 'Queried entry did not match expected: ' + JSON.stringify(entry));
          }
          done(err);
          return;
        });
      } else {
        done(err);
        return;
      }
    });
  });

  function createRefreshFunction(expectedRefreshToken, response) {
    var refreshFunction = function(entry, resource, callback) {
      if (expectedRefreshToken !== entry['refreshToken']) {
        console.log('RECIEVED:');
        console.log(entry.refreshToken);
        console.log('EXPECTED');
        console.log(expectedRefreshToken);
        assert(false, 'RefreshFunction received unexpected refresh token: ' + entry['refreshToken']);
      }
      assert(_.isFunction(callback), 'callback parameter is not a function');

      callback(null, response);
    };

    return refreshFunction;
  }

  test('add-multiple-entries-mrrt-find-refreshed-mrrt', function(done) {
    var numMRRTTokens = 5;
    fillCache(20, 5, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;
      var finalMrrt = testValues.finalMrrt;
      var authority = testValues.authority;

      var unknownScope = ['unknownScope'];
      var responseOptions = { scope : unknownScope, mrrt : true, refreshedRefresh : true };
      var refreshedResponse = util.createResponse(responseOptions);
      var refreshedRefreshToken = refreshedResponse.refreshToken;
      var refreshFunction = createRefreshFunction(finalMrrt, refreshedResponse.decodedResponse);

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);

        responses.push(refreshedResponse.cachedResponse);
        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, authority, unknownScope, cp.clientId, null, memCache, refreshFunction);
        cacheDriver.find(null, function(err, entry) {
          if (!err) {
            assert(entry, 'Expected a matching entry, but none was returned.');
            assert(entry.scope === unknownScope[0], 'Unexpected resource returned:' + entry.scope);
            assert(refreshedRefreshToken === entry['refreshToken'], 'Returned refresh token did not match expected');
            // The current logic will override the existing entry if client id, user id and authority match. 
            responses.splice(_.findWhere(responses, {scope: unknownScope[0]}), 1);
            compareInputAndCache(responses, memCache, numMRRTTokens + 1, entry.refreshToken);

            // Now ensure that the refreshed token can be successfully found in the cache.
            var query = {
              userId : entry.userId,
              clientId : cp.clientId
            };
            cacheDriver.find(query, function(err, recentlyCachedEntry) {
              if (!err) {
                assert(recentlyCachedEntry, 'Expected a returned entry but none was returned.');
                assertEntriesEqual(entry, recentlyCachedEntry, 'Token returned from cache was not the same as the one that was recently cached.');
                compareInputAndCache(responses, memCache, numMRRTTokens + 1, entry.refreshToken);
              }
              done(err);
              return;
            });
          } else {
            done(err);
            return;
          }
        });
      } else {
        done(err);
        return;
      }
    });
  });

  test('add-multiple-entries-failed-mrrt-refresh', function(done) {
    var numMRRTTokens = 5;
    fillCache(20, 5, false, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;
      var finalMrrt = testValues.finalMrrt;
      var authority = testValues.authority;

      var unknownResource = 'unknownResource';
      var refreshFunction = function(entry, resource, callback) { callback(new Error('FAILED REFRESH')); };

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);

        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, authority, unknownResource, cp.clientId, null, memCache, refreshFunction);
        cacheDriver.find(null, function(err) {
          assert(err, 'Did not receive expected error.');
          assert(-1 !== err.message.indexOf('FAILED REFRESH'), 'Error message did not contain correct text');
          compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);
          done();
          return;
        });
      } else {
        done(err);
        return;
      }
    });
  });

  function removeResponse(collection, response) {
    return _.filter(collection, function(entry) {
      if (_.isEqual(response, entry)) {
        return false;
      }
      return true;
    });
  }

  test('expired-access-token', function(done) {
    var numMRRTTokens = 5;
    fillCache(20, 5, true, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;
      var authority = testValues.authority;
      var expiredEntry = testValues.expiredEntry.cachedResponse;
      var finalMrrt = testValues.finalMrrt;

      var responseOptions = { scope : expiredEntry.scope.split(' '), refreshedRefresh : true };
      var refreshedResponse = util.createResponse(responseOptions);
      var refreshedRefreshToken = refreshedResponse.refreshToken;
      var refreshFunction = createRefreshFunction(expiredEntry['refreshToken'], refreshedResponse.decodedResponse);

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);

        responses = removeResponse(responses, expiredEntry);
        responses.push(refreshedResponse.cachedResponse);
        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, authority, expiredEntry.scope.split(' '), cp.clientId, null, memCache, refreshFunction);
        cacheDriver.find(null, function(err, entry) {
          if (!err) {
            assert(entry, 'Expected a matching entry, but none was returned.');
            assert(entry.scope === expiredEntry.scope, 'Unexpected resource returned:' + entry.scope);
            assert(refreshedRefreshToken === entry['refreshToken'], 'Returned refresh token did not match expected');
            compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);

            // Now ensure that the refreshed token can be successfully found in the cache.
            var query = {
              userId : entry.userId,
              clientId : cp.clientId
            };
            cacheDriver.find(query, function(err, recentlyCachedEntry) {
              if (!err) {
                assert(recentlyCachedEntry, 'Expected a returned entry but none was returned.');
                assertEntriesEqual(entry, recentlyCachedEntry, 'Token returned from cache was not the same as the one that was recently cached.');
                compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);
              }
              done(err);
              return;
            });
          } else {
            done(err);
            return;
          }
        });
      } else {
        done(err);
        return;
      }
    });
  });

  test('expired-access-token-failed-refresh', function(done) {
    var numMRRTTokens = 5;
    fillCache(20, 5, true, null, function(err, testValues) {
      var responses = testValues.cachedResponses;
      var memCache = testValues.memCache;
      var fakeTokenRequest = testValues.fakeTokenRequest;
      var authority = testValues.authority;
      var expiredEntry = testValues.expiredEntry.cachedResponse;
      var finalMrrt = testValues.finalMrrt;

      var refreshFunction = function(entry, resource, callback) { callback(new Error('FAILED REFRESH')); };

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);

        var cacheDriver = new CacheDriver(fakeTokenRequest._callContext, authority, expiredEntry.scope.split(' '), cp.clientId, null, memCache, refreshFunction);
        cacheDriver.find(null, function(err) {
          assert(err, 'Did not receive expected error about failed refresh.');
          assert(-1 !== err.message.indexOf('FAILED REFRESH'), 'Error message did not contain correct text');
          compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt);
          done();
          return;
        });
      } else {
        done(err);
        return;
      }
    });
  });
});