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

var util = require('./util/util');
var cp = util.commonParameters;
var testRequire = util.testRequire;

var SelfSignedJwt = testRequire('self-signed-jwt').SelfSignedJwt;


suite('self-signed-jwt', function() {
  test('create-jwt', function(done) {
    var ssjwt = new SelfSignedJwt(cp.callContext, cp.authority, cp.clienId, util.getSelfSignedCert());
    var jwt = ssjwt.create();
    var err;
    if (!jwt) {
      err = new Error('Returned empty jwt');
    }
    done(err);
  });
});