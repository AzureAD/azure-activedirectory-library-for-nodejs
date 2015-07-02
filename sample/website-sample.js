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

var express = require('express');
var logger = require('connect-logger');
var cookieParser = require('cookie-parser');
var session = require('cookie-session');
var fs = require('fs');
var crypto = require('crypto');
var https = require('https');

var AuthenticationContext = require('../lib/adal.js').AuthenticationContext;

var app = express();
app.use(logger());
app.use(cookieParser('a deep secret'));
app.use(session({secret: '1234567890QWERTY'}));

var options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

app.get('/', function(req, res) {
    if (req.query.code) {
        var authenticationContext = new AuthenticationContext(authorityUrl);
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        authenticationContext.options = {
            http : {
                proxy : 'http://127.0.0.1:8888'
            }
        };

        authenticationContext.acquireTokenWithAuthorizationCode(req.query.code, redirectUri, scope, sampleParameters.clientId, sampleParameters.clientSecret, function (err, response) {
            var message = '';
            if (err) {
                message = 'error: ' + err.message + '\n';
            }
            message += 'response: ' + JSON.stringify(response);
            
            if (err) {
                res.send(message);
                return;
            }
            
            //Later, if the access token is expired it can be refreshed.
            authenticationContext.acquireTokenWithRefreshToken(response.refreshToken, sampleParameters.clientId, sampleParameters.clientSecret, scope, function (refreshErr, refreshResponse) {
                if (refreshErr) {
                    message += 'refreshError: ' + refreshErr.message + '\n';
                }
                message += 'refreshResponse: ' + JSON.stringify(refreshResponse);
                
                res.send(message);
            });
        });
    }
    else {
        res.redirect('login');
    }
});

/*
 * You can override the default account information by providing a JSON file
 * with the same parameters as the sampleParameters variable below.  Either
 * through a command line argument, 'node sample.js parameters.json', or
 * specifying in an environment variable.
 * {
 *   "tenant" : "rrandallaad1.onmicrosoft.com",
 *   "authorityHostUrl" : "https://login.windows.net",
 *   "clientId" : "624ac9bd-4c1c-4686-aec8-e56a8991cfb3",
 *   "clientSecret" : "verySecret="
 * }
 */
var parametersFile = process.argv[2] || process.env['ADAL_SAMPLE_PARAMETERS_FILE'];

var sampleParameters;
if (parametersFile) {
  var jsonFile = fs.readFileSync(parametersFile);
  if (jsonFile) {
    sampleParameters = JSON.parse(jsonFile);
  } else {
    console.log('File not found, falling back to defaults: ' + parametersFile);
  }
}

if (!parametersFile) {
  sampleParameters = {
    tenant : 'common',
    authorityHostUrl : 'https://login.microsoftonline.com',
    clientId : 'e1eb8a8d-7b0c-4a14-9313-3f2c25c82929',
    username : '',
    password : '',
    clientSecret: ''
  };
}

var authorityUrl = sampleParameters.authorityHostUrl + '/' + sampleParameters.tenant;
var redirectUri = 'https://cid.azurewebsites.net';
var resource = 'https://outlook.office.com';
var scope = ['openid','https://outlook.office.com/Mail.Read'];

var templateAuthzUrl = 'https://login.microsoftonline.com/' + sampleParameters.tenant + '/oauth2/v2.0/authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&state=<state>&x-client-SKU=Js&x-client-Ver=1.0.0&slice=testslice&msaproxy=true&scope=openid%20https%3A%2F%2Foutlook.office.com%2FMail.Read';

app.get('/', function(req, res) {
  res.redirect('/login');
});

app.get('/login', function(req, res) {
  console.log(req.cookies);

  res.cookie('acookie', 'this is a cookie');

  res.send('\
<head>\
  <title>FooBar</title>\
</head>\
<body>\
  <a href="./auth">Login</a>\
</body>\
    ');
});

function createAuthorizationUrl(state) {
  var authorizationUrl = templateAuthzUrl.replace('<client_id>', sampleParameters.clientId);
  authorizationUrl = authorizationUrl.replace('<redirect_uri>',redirectUri);
  authorizationUrl = authorizationUrl.replace('<state>', state);
  return authorizationUrl;
}

// Clients get redirected here in order to create an OAuth authorize url and redirect them to AAD.
// There they will authenticate and give their consent to allow this app access to
// some resource they own.
app.get('/auth', function(req, res) {
  crypto.randomBytes(48, function(ex, buf) {
    var token = buf.toString('base64').replace(/\//g,'_').replace(/\+/g,'-');

    res.cookie('authstate', token);
    var authorizationUrl = createAuthorizationUrl(token);

    res.redirect(authorizationUrl);
  });
});

https.createServer(options, app).listen(3000);

console.log('listening on 3000');