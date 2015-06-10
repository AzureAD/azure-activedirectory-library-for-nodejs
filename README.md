# Windows Azure Active Directory Authentication Library (ADAL) for Node.js
The ADAL for node.js library makes it easy for node.js applications to authenticate to AAD in order to access AAD protected web resources.  It supports 3 authentication modes shown in the quickstart code below.

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the Apache 2.0 license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

## Quick Start
### Installation

``` $ npm install adal-node ```

### Authorization Code

See the [website sample](https://github.com/MSOpenTech/azure-activedirectory-library-for-nodejs/blob/master/sample/website-sample.js) for a complete bare bones express based web site that makes use of the code below.

```javascript
var AuthenticationContext = require('adal-node').AuthenticationContext;

var clientId = 'yourClientIdHere';
var clientSecret = 'yourAADIssuedClientSecretHere'
var redirectUri = 'yourRedirectUriHere';
var authorityHostUrl = 'https://login.windows.net';
var tenant = 'myTenant';
var authorityUrl = authorityHostUrl + '/' + tenant;
var redirectUri = 'http://localhost:3000/getAToken';
var resource = '00000002-0000-0000-c000-000000000000';
var templateAuthzUrl = 'https://login.windows.net/' + 
                        tenant + 
                        '/oauth2/authorize?response_type=code&client_id=' +
                        clientId + 
                        '&redirect_uri=' + 
                        redirectUri + '
                        &state=<state>&resource=' + 
                        resource;

function createAuthorizationUrl(state) {
  return templateAuthzUrl.replace('<state>', state);
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

  authenticationContext.acquireTokenWithAuthorizationCode(
    req.query.code,
    redirectUri,
    resource,
    clientId, 
    clientSecret,
    function(err, response) {
      var errorMessage = '';
      if (err) {
        errorMessage = 'error: ' + err.message + '\n';
      }
      errorMessage += 'response: ' + JSON.stringify(response);
      res.send(errorMessage);
    }
  );
});
```

### Server to Server via Client Credentials

See the [client credentials sample](https://github.com/MSOpenTech/azure-activedirectory-library-for-nodejs/blob/master/sample/client-credentials-sample.js).

```javascript
var adal = require('adal-node').AuthenticationContext;

var authorityHostUrl = 'https://login.windows.net';
var tenant = 'myTenant';
var authorityUrl = authorityHostUrl + '/' + tenant;
var clientId = 'yourClientIdHere';
var clientSecret = 'yourAADIssuedClientSecretHere'
var resource = '00000002-0000-0000-c000-000000000000';

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
