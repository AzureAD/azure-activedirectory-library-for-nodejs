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

import * as assert from "assert";

const util = require('./util/util');
const testRequire = util.testRequire;
const MemoryCache = testRequire('memory-cache');

suite('MemoryCache', function () {

  test('add creates a new entry if the cache is empty', function(done) {
    var cache = new MemoryCache();
    var cacheEntry = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      clientSecret: 'clientSecret*&^(?&',
      expiresOnDate: Date.now()
    };

    cache.add([cacheEntry], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      assert(cache._entries.length == 1, 'Entry not added');
      done();
    });
  });

  test('add does not create a duplicate', function(done) {
    var cache = new MemoryCache();
    var cacheEntry = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      clientSecret: 'clientSecret*&^(?&',
      expiresOnDate: Date.now()
    };

    cache.add([cacheEntry], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 1, 'Duplicate created');
        done();
      });
    });
  });

  /*
   * Two entries requested milliseconds apart will have different expires on dates. They will both get attempted to add
   * to the Cache. Ensure they are not duplicated into the cache entries list.
   */
  test('add considers entries with equal _clientId, _authority, resource, userId to be equivilent', function(done) {
    var cache = new MemoryCache();
    var cacheEntry1 = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      userId: 'abc',
      expiresOnDate: Date.now()
    };

    var cacheEntry2 = {
      _clientId: cacheEntry1._clientId,
      resource: cacheEntry1.resource,
      _authority: cacheEntry1._authority,
      userId: cacheEntry1.userId,
      expiresOnDate: cacheEntry1.expiresOnDate + 10
    };

    cache.add([cacheEntry1], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry2], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 1, 'Duplicate created');
        done();
      });
    });
  });

  test('entries with different _clientId values are added', function(done) {
    var cache = new MemoryCache();
    var cacheEntry1 = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      userId: 'abc',
      expiresOnDate: Date.now()
    };

    var cacheEntry2 = {
      _clientId: 'other-client-id',
      resource: cacheEntry1.resource,
      _authority: cacheEntry1._authority,
      userId: cacheEntry1.userId,
      expiresOnDate: cacheEntry1.expiresOnDate
    };

    cache.add([cacheEntry1], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry2], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 2, 'Entry not added');
        done();
      });
    });
  });

  test('entries with different resource values are added', function(done) {
    var cache = new MemoryCache();
    var cacheEntry1 = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      userId: 'abc',
      expiresOnDate: Date.now()
    };

    var cacheEntry2 = {
      _clientId: cacheEntry1._clientId,
      resource: 'different resource',
      _authority: cacheEntry1._authority,
      userId: cacheEntry1.userId,
      expiresOnDate: cacheEntry1.expiresOnDate
    };

    cache.add([cacheEntry1], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry2], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 2, 'Entry not added');
        done();
      });
    });
  });

  test('entries with different _authority values are added', function(done) {
    var cache = new MemoryCache();
    var cacheEntry1 = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      userId: 'abc',
      expiresOnDate: Date.now()
    };

    var cacheEntry2 = {
      _clientId: cacheEntry1._clientId,
      resource: cacheEntry1.resource,
      _authority: 'differnt authority',
      userId: cacheEntry1.userId,
      expiresOnDate: cacheEntry1.expiresOnDate
    };

    cache.add([cacheEntry1], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry2], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 2, 'Entry not added');
        done();
      });
    });
  });

  test('entries with different userId values are added', function(done) {
    var cache = new MemoryCache();
    var cacheEntry1 = {
      _clientId: 'clien&&???tId',
      resource: '00000002-0000-0000-c000-000000000000',
      _authority: 'authority',
      userId: 'abc',
      expiresOnDate: Date.now()
    };

    var cacheEntry2 = {
      _clientId: cacheEntry1._clientId,
      resource: cacheEntry1.resource,
      _authority: cacheEntry1._authority,
      userId: 'different user',
      expiresOnDate: cacheEntry1.expiresOnDate
    };

    cache.add([cacheEntry1], function(err: any) {
      var stack = err ? err.stack : null;
      assert(!err, 'Received unexpected error: ' + stack);
      cache.add([cacheEntry2], function(err: any) {
        var stack = err ? err.stack : null;
        assert(!err, 'Received unexpected error: ' + stack);

        assert(cache._entries.length == 2, 'Entry not added');
        done();
      });
    });
  });
});