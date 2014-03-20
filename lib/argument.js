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

var argumentValidation = {
  /**
   * Throws is the passed in parameter is not a string.
   * @param  {string} param   The parameter to validate.
   * @param  {string} name    The name of the parameter being validated.
   * @throws {Error} If the parameter is not a valid string.
   */
  validateStringParameter : function(param, name) {
    if (!param) {
      throw new Error('The ' + name + ' parameter is required.');
    }
    if (!_.isString(param)) {
      throw new Error('The ' + name + ' parameter must be of type String.');
    }
  },

  /**
   * Validates that the callback passed in {@link AuthenticationContext.acquireToken} is a function
   * @param  {AcquireTokenCallback} callback
   * @throws {Error} If the callback parameter is not a function
   */
  validateCallbackType : function(callback) {
    if (!callback || !_.isFunction(callback)) {
      throw new Error('acquireToken requires a function callback parameter.');
    }
  }
};

module.exports = argumentValidation;
