# Windows Azure Active Directory Authentication Library (ADAL) for Node.js
The ADAL for node.js library makes it easy for node.js applications to authenticate to AAD in order to access AAD protected web resources.  It supports 3 authentication modes shown in the quickstart code below.

## Quick Start

### Authorization Code

See the [website sample](https://github.com/MSOpenTech/azure-activedirectory-library-for-nodejs/blob/master/sample/website-sample.js) for a complete bare bones express based web site that makes use of the code below.

```javascript

var AuthenticationContext = require('adal-node').AuthenticationContext;

var clientId = 'yourClientIdHere';
var redirectUri = 'yourRedirectUriHere';
var authorityHostUrl = 'https://login.windows.net';
var tenant = 'myTenant';
var authorityUrl = authorityHostUrl + '/' + tenant;
var redirectUri = 'http://localhost:3000/getAToken';
var resource = '00000002-0000-0000-c000-000000000000';
var templateAuthzUrl = 'https://login.windows.net/' + tenant + '/oauth2/authorize?response_type=code&client_id=' + clientId + '&redirect_uri=' + redirectUri + '&state=<state>&resource=' + resource;

function createAuthorizationUrl(state) {
  var authorizationUrl = templateAuthzUrl.replace('<client_id>', sampleParameters.clientId);
  authorizationUrl = authorizationUrl.replace('<redirect_uri>',redirectUri);
  authorizationUrl = authorizationUrl.replace('<state>', state);
  authorizationUrl = authorizationUrl.replace('<resource>', resource);
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

// After consent is granted AAD redirects here.  The ADAL library is invoked via the
// AuthenticationContext and retrieves an access token that can be used to access the
// user owned resource.
app.get('/getAToken', function(req, res) {
  if (req.cookies.authstate !== req.query.state) {
    res.send('error: state does not match');
  }
  var authenticationContext = new AuthenticationContext(authorityUrl);
  authenticationContext.acquireTokenWithAuthorizationCode(req.query.code, redirectUri, resource, sampleParameters.clientId, sampleParameters.clientSecret, function(err, response) {
    var errorMessage = '';
    if (err) {
      errorMessage = 'error: ' + err.message + '\n';
    }
    errorMessage += 'response: ' + JSON.stringify(response);
    res.send(errorMessage);
  });
});
```

### Server to Server via Client Credentials

See the [client credentials sample](https://github.com/MSOpenTech/azure-activedirectory-library-for-nodejs/blob/master/sample/client-credentials-sample.js).

```javascript

var adal = require('adal-node').AuthenticationContext;

var tenant = 'myTenant';
var authorityUrl = 'https://windows.login.net/' + tenant;
var clientId = 'myClientId';
var clientSecret = 'aadIssuedClientSecret';

var resource = '00000002-0000-0000-c000-000000000000';

turnOnLogging();

var context = new AuthenticationContext(authorityUrl);

context.acquireTokenWithClientCredentials(resource, clientId, clientSecret, function(err, tokenResponse) {
  if (err) {
    console.log('well that didn\'t work: ' + err.stack);
  } else {
    console.log(tokenResponse);
  }
});
```

## License
Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 