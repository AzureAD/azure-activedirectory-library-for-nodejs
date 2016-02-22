'use strict';

var _ = require('underscore');
require('date-utils');
var fs = require('fs');
var nock = require('nock');
var querystring = require('querystring');
var url = require('url');

var adaldir = process.env.ADAL_COV ? '../../lib-cov/' : '../../lib/';

function testRequire(file) {
  return require(adaldir + file);
}

nock.disableNetConnect();

var adal = testRequire('adal');
var log = testRequire('log');

var util = {};

var successResponse = {
  'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiIwMDAwMDAwMi0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MmYwMzQ3MS02N2MxLTRjNTAtYjlkMS0xMzQ1MDc5ZDk3NzQvIiwiaWF0IjoxMzc4NjAxMTY4LCJuYmYiOjEzNzg2MDExNjgsImV4cCI6MTM3ODYyOTk2OCwidmVyIjoiMS4wIiwidGlkIjoiNjJmMDM0NzEtNjdjMS00YzUwLWI5ZDEtMTM0NTA3OWQ5Nzc0Iiwib2lkIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3Iiwic3ViIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3IiwiYXBwaWQiOiI1YzI1ZDFiZi1iMjMyLTQwMzUtYjZiOS0yYjdlN2U4MzQ2ZDYiLCJhcHBpZGFjciI6IjEifQ.qXM7f9TTiLApxVMwaSrISQQ6UAnfKvKhoIlN9rB0Eff2VXvIWKGRsclPkMQ5x42BQz2N6pSXEsN-LsNCZlQ76Rc3rVRONzeCYh7q_NXcCJG_d6SJTtV5GBfgqFlgT8UF5rblabbMdOiOrddvJm048hWt2Nm3qD3QjQdPBlD7Ksn-lUR1jEJPIqDaBjGom8RawrZTW6X1cy1Kr8mEYFkxcbU91k_RZUumONep9FTR8gfPkboeD8zyvOy64UeysEtcuaNCfhHSBFcwC8MwjUr5r_T7au7ywAcYDOVgoa7oF_dN1JNweiDoNNZ9tyUS-RY3sa3-gXk77gRxpA4CkpittQ',
  'token_type': 'Bearer',
  'expires_in': 28800,
  'resource': '00000002-0000-0000-c000-000000000000',
};

var refreshToken = 'AwABAAAAvPM1KaPlrEqdFSBzjqfTGCDeE7YHWD9jkU2WWYKLjxu928QAbkoFyWpgJLFcp65DcbBqOSYVq5Ty_60YICIdFw61SG4-eT1nWHNOPdzsL2ZzloUsp2DpqlIr1s5Z3953oQBi7dOqiHk37NXQqmNEJ7MfmDp6w3EOa29EPARvjGIHFgtICW1-Y82npw1v1g8Ittb02pksNU2XzH2X0E3l3TuSZWsX5lpl-kfPOc8zppU6bwvT-VOPHZVVLQedDIQZyOiFst9HLUjbiIvBgV7tNwbB4H5yF56QQscz49Nrb3g0ibuNDo7efFawLzNoVHzoTrOTcCGSG1pt8Z-npByrEe7vg1o4nNFjspuxlyMGdnYRAnaZfvgzqROP_m7ZqSd6IAA';
var successResponseWithRefresh = _.clone(successResponse);
_.extend(successResponseWithRefresh, {
  'scope' : '62e90394-69f5-4237-9190-012177145e10',
  'refresh_token' : refreshToken
});

var encodedIdToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.';

var parsedIdToken = {
  'tenantId' : 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'userId' : 'rrandall@rrandallaad1.onmicrosoft.com',
  'givenName' : 'Rich',
  'familyName' : 'Randall',
  'isUserIdDisplayable' : true,
  'oid': 'a443204a-abc9-4cb8-adc1-c0dfc12300aa',
};


var decodedIdToken = {
  aud: 'e958c09a-ac37-4900-b4d7-fb3eeaf7338d',
  iss: 'https://sts.windows.net/cceba14c-6a00-49ac-b806-84de52bf1d42/',
  iat: 1391645458,
  nbf: 1391645458,
  exp: 1391649358,
  ver: '1.0',
  tid: 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  oid: 'a443204a-abc9-4cb8-adc1-c0dfc12300aa',
  upn: 'rrandall@rrandallaad1.onmicrosoft.com',
  'unique_name': 'rrandall@rrandallaad1.onmicrosoft.com',
  sub: '4gTv4EtoYW-DTow0bDnJd1AA4sfChBbjermqt6Q_Za4',
  'family_name': 'Randall',
  'given_name': 'Rich'
};

var encodedIdTokenUrlSafe = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoiZm9vYmFyQHNvbWVwbGFjZWVsc2UuY29tIiwidW5pcXVlX25hbWUiOiJycmFuZGFsbEBycmFuZGFsbGFhZDEub25taWNyb3NvZnQuY29tIiwic3ViIjoiNGdUdjRFdG9ZVy1EVG93MGJEbkpkMUFBNHNmQ2hCYmplcm1xdDZRX1phNCIsImZhbWlseV9uYW1lIjoiUmFuZGFsbCIsImdpdmVuX25hbWUiOiJSaTw_Y2gifQ==.';

var parsedIdTokenUrlSafe = {
  'tenantId' : 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'userId' : 'foobar@someplaceelse.com',
  'givenName' : 'Ri<?ch',
  'familyName' : 'Randall',
  'isUserIdDisplayable' : true
};

var decodedTokenUrlSafeTest = {
  aud: 'e958c09a-ac37-4900-b4d7-fb3eeaf7338d',
  iss: 'https://sts.windows.net/cceba14c-6a00-49ac-b806-84de52bf1d42/',
  iat: 1391645458,
  nbf: 1391645458,
  exp: 1391649358,
  ver: '1.0',
  tid: 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  oid: 'a443204a-abc9-4cb8-adc1-c0dfc12300aa',
  upn: 'foobar@someplaceelse.com',
  'unique_name': 'rrandall@rrandallaad1.onmicrosoft.com',
  sub: '4gTv4EtoYW-DTow0bDnJd1AA4sfChBbjermqt6Q_Za4',
  'family_name': 'Randall',
  'given_name': 'Ri<?ch'
};

var parameters = {};
parameters.tenant = 'rrandallaad1.onmicrosoft.com';
parameters.clientId = 'clien&&???tId';
parameters.clientSecret = 'clientSecret*&^(?&';
parameters.resource = '00000002-0000-0000-c000-000000000000';
parameters.evoEndpoint = 'https://login.windows.net';
parameters.username = 'rrandall@' + parameters.tenant;
parameters.password = 'Atestpass!@#$';
parameters.authorityHosts = {
  global : 'login.windows.net',
  china : 'login.chinacloudapi.cn',
  gov : 'login.cloudgovapi.us'
};
parameters.language = 'en';
parameters.deviceCode = 'ABCDE:device_code';

parameters.refreshToken = refreshToken;

// This is a default authority to be used in tests that don't care that there are multiple.
parameters.authority = parameters.evoEndpoint;
parameters.authorityTenant = parameters.authority + '/' + parameters.tenant;
parameters.adfsUrlNoPath = 'https://adfs.federatedtenant.com';
parameters.adfsMexPath = '/adfs/services/trust/mex';
parameters.adfsWsTrustPath = '/adfs/services/trust/13/usernamemixed';
parameters.adfsWsTrustPath2005 = '/adfs/services/trust/2005/usernamemixed';
parameters.adfsMex = parameters.adfsUrlNoPath + parameters.adfsMexPath;
parameters.adfsWsTrust = parameters.adfsUrlNoPath + parameters.adfsWsTrustPath;
parameters.adfsWsTrust2005 = parameters.adfsUrlNoPath + parameters.adfsWsTrustPath2005;

parameters.successResponse = successResponse;
parameters.successResponseWithRefresh = successResponseWithRefresh;
parameters.authUrl = url.parse(parameters.evoEndpoint + '/' + parameters.tenant);
parameters.tokenPath = '/oauth2/token';
parameters.extraQP = '?api-version=1.0';
parameters.tokenUrlPath = parameters.authUrl.pathname + parameters.tokenPath + parameters.extraQP;
parameters.deviceCodePath = '/oauth2/devicecode'
parameters.deviceCodeUrlPath = parameters.authUrl.pathname + parameters.deviceCodePath + parameters.extraQP;
parameters.authorizePath = '/oauth/authorize';
parameters.authorizeUrlPath = parameters.authUrl.pathname + parameters.authorizePath;
parameters.authorizeUrl = parameters.authUrl.href + parameters.authorizePath;
parameters.instanceDiscoverySuccessResponse = {
  'tenant_discovery_endpoint' : parameters.authority
};
parameters.userRealmPathTemplate = '/common/UserRealm/<user>';

parameters.userRealmResponseFederated = '{\"account_type\":\"federated\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"' + parameters.adfsMex + '\",\"federation_active_auth_url\":\"' + parameters.adfsWsTrust + '\",\"ver\":\"0.8\"}';
parameters.userRealmResponseManaged = '{\"account_type\":\"managed\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"' + parameters.adfsMex + '\",\"federation_active_auth_url\":\"' + parameters.adfsWsTrust + '\",\"ver\":\"0.8\"}';
parameters.MexFile = __dirname + '/../mex/common.mex.xml';

// These two files go together.  Editing one without changing the other will break the test.
parameters.RSTRFile = __dirname + '/../wstrust/common.rstr.xml';
parameters.AssertionFile = __dirname + '/../wstrust/common.base64.encoded.assertion.txt';
parameters.logContext = { correlationId : 'test-correlation-id-123456789' };
parameters.callContext = { _logContext : parameters.logContext };


util.getSelfSignedCert = function() {
  var privatePem = fs.readFileSync(__dirname + '/self-signed-cert.pem', { encoding : 'utf8'});
  return privatePem;
};

parameters.certHash = 'C1:5D:EA:86:56:AD:DF:67:BE:80:31:D8:5E:BD:DC:5A:D6:C4:36:E1';
parameters.nowDate = new Date(1418433646179);
parameters.jwtId = '09841beb-a2c2-4777-a347-34ef055238a8';
parameters.expectedJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IndWM3FobGF0MzJlLWdESFlYcjNjV3RiRU51RSJ9.eyJhdWQiOiJodHRwczovL2xvZ2luLndpbmRvd3MubmV0L3JyYW5kYWxsYWFkMS5vbm1pY3Jvc29mdC5jb20vb2F1dGgyL3Rva2VuIiwiaXNzIjoiY2xpZW4mJj8_P3RJZCIsInN1YiI6ImNsaWVuJiY_Pz90SWQiLCJuYmYiOjE0MTg0MzM2NDYsImV4cCI6MTQxODQzNDI0NiwianRpIjoiMDk4NDFiZWItYTJjMi00Nzc3LWEzNDctMzRlZjA1NTIzOGE4In0.dgF0TRlcASgTMp_1dlm8vd7tudr6n40VeuOQGFnz566s3n76WR_jJDBBBKlYeqc9gwCPFOzrLVAJehVYZ3N7YPzVdulf47rLoQdAp8R_p4Q4hdBZuIzfgDWwXjnP9x_NlfzezEYE4r8KTS2g5BBzPmx538AfIdNM93hWIxQySZGWY5UAhTkT1qE1ce1Yjo1M2HqzEJhTg5TTyfrnDtNxFxmzYhSyA9B41lB5kBuJTXUWXPrr-6eG8cEUOS-iiH7YB1Tf4J7_9JQloevTiOrfv4pSp6xLLXm2ntNBg3gaKsGKdYd-3tsCG0mHn7BzL0b-QCLalkUr8KtgtLqkxuAiLQ';
parameters.cert = util.getSelfSignedCert();


util.commonParameters = parameters;

util.testRequire = testRequire;

var correlationIdRegex = /[^\s]+/;
util.testCorrelationId = correlationIdRegex;
util.setCorrelationId = function(correlationId) {
  util.testCorrelationId = correlationId || correlationIdRegex;
};

util.turnOnLogging = function(level, logFunc) {
  var consoleLog = function(level, message, error) {
    console.log(message);
    if (error) {
      console.log(error);
    }
  };

  var log = adal.Logging;
  var loggingFunction = logFunc || consoleLog;
  var loggingLevel = level || log.LOGGING_LEVEL.VERBOSE;
  log.setLoggingOptions(
  {
    level : loggingLevel,
    log : loggingFunction
  });
};

util.resetLogging = function() {
  var log = adal.Logging;
  log.setLoggingOptions();
};

var TOKEN_RESPONSE_MAP = {};
TOKEN_RESPONSE_MAP['token_type'] = 'tokenType';
TOKEN_RESPONSE_MAP['access_token'] = 'accessToken';
TOKEN_RESPONSE_MAP['refresh_token'] = 'refreshToken';
TOKEN_RESPONSE_MAP['created_on'] = 'createdOn';
TOKEN_RESPONSE_MAP['expires_on'] = 'expiresOn';
TOKEN_RESPONSE_MAP['expires_in'] = 'expiresIn';
TOKEN_RESPONSE_MAP['error'] = 'error';
TOKEN_RESPONSE_MAP['error_description'] = 'errorDescription';
TOKEN_RESPONSE_MAP['resource'] = 'resource';

var DEVICE_CODE_RESPONSE_MAP = {};
DEVICE_CODE_RESPONSE_MAP['device_code'] = 'deviceCode';
DEVICE_CODE_RESPONSE_MAP['user_code'] = 'userCode';
DEVICE_CODE_RESPONSE_MAP['verification_url'] = 'verificationUrl';
DEVICE_CODE_RESPONSE_MAP['interval'] = 'interval';
DEVICE_CODE_RESPONSE_MAP['expires_in'] = 'expiresIn';
DEVICE_CODE_RESPONSE_MAP['error'] = 'error';
DEVICE_CODE_RESPONSE_MAP['error_description'] = 'errorDescription';

function mapFields(inObj, outObj, map) {
  for (var key in inObj) {
    if (map[key]) {
      var mappedKey = map[key];
      outObj[mappedKey] = inObj[key];
    }
  }
}

/**
 * Create response based on the given options and iteration number. 
 * @options Options is used to flex the reponse creation, i.e authority, resource and isMRRT. 
 * @param iteration Iteraton will be used to create a distinct token for each value of iteration and it will always return that same token 
 *                  for same value of iteration. 
 */
util.createResponse = function(options, iteration) {
  options = options || {};

  var authority = options.authority || parameters.authorityTenant;

  var baseResponse = {
    'token_type' : 'Bearer',
    'expires_in': 28800
  };

  var resource = options.resource || parameters.resource;
  var iterated = {
    'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiIwMDAwMDAwMi0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MmYwMzQ3MS02N2MxLTRjNTAtYjlkMS0xMzQ1MDc5ZDk3NzQvIiwiaWF0IjoxMzc4NjAxMTY4LCJuYmYiOjEzNzg2MDExNjgsImV4cCI6MTM3ODYyOTk2OCwidmVyIjoiMS4wIiwidGlkIjoiNjJmMDM0NzEtNjdjMS00YzUwLWI5ZDEtMTM0NTA3OWQ5Nzc0Iiwib2lkIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3Iiwic3ViIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3IiwiYXBwaWQiOiI1YzI1ZDFiZi1iMjMyLTQwMzUtYjZiOS0yYjdlN2U4MzQ2ZDYiLCJhcHBpZGFjciI6IjEifQ.qXM7f9TTiLApxVMwaSrISQQ6UAnfKvKhoIlN9rB0Eff2VXvIWKGRsclPkMQ5x42BQz2N6pSXEsN-LsNCZlQ76Rc3rVRONzeCYh7q_NXcCJG_d6SJTtV5GBfgqFlgT8UF5rblabbMdOiOrddvJm048hWt2Nm3qD3QjQdPBlD7Ksn-lUR1jEJPIqDaBjGom8RawrZTW6X1cy1Kr8mEYFkxcbU91k_RZUumONep9FTR8gfPkboeD8zyvOy64UeysEtcuaNCfhHSBFcwC8MwjUr5r_T7au7ywAcYDOVgoa7oF_dN1JNweiDoNNZ9tyUS-RY3sa3-gXk77gRxpA4CkpittQ',
    'resource' : resource
  };

  if (!options.noRefresh) {
    if (options.refreshedRefresh) {
      iterated['refresh_token'] = 'AwABAAAAvPM1KaPlrEqdFSBzjqfTGCDeE7YHWD9jkU2WWYKLjxu928QAbkoFyWp&yfPNft8DcbBqOSYVq5Ty_60YICIdFw61SG4-eT1nWHNOPdzsL2ZzloUsp2DpqlIr1s5Z3953oQBi7dOqiHk37NXQqmNEJ7MfmDp6w3EOa29EPARvjGIHFgtICW1-Y82npw1v1g8Ittb02pksNU2XzH2X0E3l3TuSZWsX5lpl-kfPOc8zppU6bwvT-VOPHZVVLQedDIQZyOiFst9HLUjbiIvBgV7tNwbB4H5yF56QQscz49Nrb3g0ibuNDo7efFawLzNoVHzoTrOTcCGSG1pt8Z-npByrEe7vg1o4nNFjspuxlyMGdnYRAnaZfvgzqROP_m7ZqSd6IAA';
    } else {
      iterated['refresh_token'] = parameters.refreshToken;
    }
  }

  if (iteration) {
    var iteratedKeys = _.keys(iterated);
    for (var i = 0; i < iteratedKeys.length; i++) {
      var key = iteratedKeys[i];
      iterated[key] = iterated[key] + iteration;
    }
  }

  _.extend(baseResponse, iterated);

  if (!options.mrrt) {
    delete baseResponse.resource;
  }

  var dateNow = new Date();
  var wireResponse = _.clone(baseResponse);
  wireResponse['created_on'] = dateNow.getTime();

  var decodedResponse = {};
  mapFields(wireResponse, decodedResponse, TOKEN_RESPONSE_MAP);
  decodedResponse['createdOn'] = dateNow;

  if (!options.noIdToken) {
    wireResponse['id_token'] = options.urlSafeUserId ? encodedIdTokenUrlSafe : encodedIdToken;
    var parsedUserInfo = options.urlSafeUserId ? parsedIdTokenUrlSafe : parsedIdToken;
    _.extend(decodedResponse, parsedUserInfo);
  }

  var expiresOnDate;
  if (options.expired) {
    expiresOnDate = Date.yesterday();
  } else {
    expiresOnDate = (new Date()).addSeconds(decodedResponse['expiresIn']);
  }
  decodedResponse['expiresOn'] = expiresOnDate;

  var cachedResponse = _.clone(decodedResponse);

  cachedResponse['_clientId'] = parameters.clientId;
  cachedResponse['_authority'] = authority;
  cachedResponse['resource'] = iterated['resource'];
  if (options.mrrt) {
    cachedResponse.isMRRT = true;
  }

  return {
    wireResponse : wireResponse,
    decodedResponse : decodedResponse,
    cachedResponse : cachedResponse,
    decodedIdToken : decodedIdToken,
    resource : iterated['resource'],
    refreshToken : iterated['refresh_token'],
    clientId : cachedResponse['_clientId'],
    authority : authority
  };
};

util.createDeviceCodeResponse = function (options, iteration) {
    options = options || {};
    
    var authority = options.authority || parameters.authorityTenant;
    var resource = options.resource || parameters.resource;

    var wireResponse = {};
    wireResponse['expires_in'] = 28800;
    wireResponse['device_code'] = 'device_code:12345';
    wireResponse['user_code'] = 'user_code:12345';
    wireResponse['verification_url'] = 'go:to:verify';
    wireResponse['interval'] = 5;

    var decodedResponse = {};
    mapFields(wireResponse, decodedResponse, DEVICE_CODE_RESPONSE_MAP);

    return {
       wireResponse : wireResponse, 
       decodedResponse : decodedResponse
    };
};

util.compareQueryStrings = function(left, right) {
  var leftParameters = querystring.parse(left);
  var rightParameters = querystring.parse(right);
  return _.isEqual(leftParameters, rightParameters);
};

util.filterQueryString = function(expected, received) {
  return util.compareQueryStrings(expected, received) ? expected : received;
};

util.removeQueryStringIfMatching = function(path, query) {
  var pathUrl = url.parse(path);
  return util.compareQueryStrings(pathUrl.query, query) ? pathUrl.pathname : path;
};

function valExists(val) {
  return val;
}

util.matchStandardRequestHeaders = function(nockRequest) {
  nockRequest.matchHeader('x-client-SKU', 'Node')
             .matchHeader('x-client-Ver', function(ver) {
              return (ver && ver.indexOf('0.') === 0);
             })
             .matchHeader('x-client-OS', valExists)
             .matchHeader('x-client-CPU', valExists)
             .matchHeader('client-request-id', util.testCorrelationId);
};

util.setupExpectedOAuthResponse = function(queryParameters, tokenPath, httpCode, returnDoc, authorityEndpoint) {
  var query = querystring.stringify(queryParameters);

  var authEndpoint = this.getNockAuthorityHost(authorityEndpoint);
  var tokenRequest = nock(authEndpoint)
                         .filteringRequestBody(function(body) {
                            return util.filterQueryString(query, body);
                          })
                         .post(tokenPath, query)
                         .reply(httpCode, returnDoc, { 'client-request-id' : util.testCorrelationId });

  util.matchStandardRequestHeaders(tokenRequest);

  return tokenRequest;
};

util.setupExpectedClientCredTokenRequestResponse = function(httpCode, returnDoc, authorityEndpoint) {
  var authEndpoint = authorityEndpoint || parameters.authority;

  var queryParameters = {};
  queryParameters['grant_type'] = 'client_credentials';
  queryParameters['client_id'] = parameters.clientId;
  queryParameters['client_secret'] = parameters.clientSecret;
  queryParameters['resource'] = parameters.resource;

  return util.setupExpectedOAuthResponse(queryParameters, parameters.tokenUrlPath, httpCode, returnDoc, authEndpoint);
};

util.setupExpectedInstanceDiscoveryRequest = function(httpCode, discoveryHost, returnDoc, authority) {
  var instanceDiscoveryUrl = {};
  instanceDiscoveryUrl.protocol = 'https:';
  instanceDiscoveryUrl.host = discoveryHost;
  instanceDiscoveryUrl.pathname = '/common/discovery/instance';
  instanceDiscoveryUrl.query = {};
  instanceDiscoveryUrl.query['authorization_endpoint'] = url.format(authority);
  instanceDiscoveryUrl.query['api-version'] = '1.0';

  instanceDiscoveryUrl = url.parse(url.format(instanceDiscoveryUrl));

  var instanceDiscoveryEndpoint = this.trimPathFromUrl(instanceDiscoveryUrl);

  var discoveryRequest = nock(instanceDiscoveryEndpoint)
                         .get(instanceDiscoveryUrl.path)
                         .reply(httpCode, returnDoc);

  util.matchStandardRequestHeaders(discoveryRequest);

  return discoveryRequest;
};

util.setupExpectedInstanceDiscoveryRequestCommon = function() {
  return util.setupExpectedInstanceDiscoveryRequest(
    200,
    parameters.authority,
    parameters.instanceDiscoverySuccessResponse,
    parameters.authority);
};

util.setupExpectedUserRealmResponse = function(httpCode, returnDoc, authority) {
  var userRealmAuthority = authority || parameters.authority;
  userRealmAuthority = this.trimPathFromUrl(userRealmAuthority);

  var userRealmPath = parameters.userRealmPathTemplate.replace('<user>', encodeURIComponent(parameters.username));
  var query = 'api-version=1.0';

  var userRealmRequest = nock(userRealmAuthority)
                         .filteringPath(function(path) {
                            return util.removeQueryStringIfMatching(path, query);
                          })
                          .get(userRealmPath)
                          .reply(200, returnDoc);

  util.matchStandardRequestHeaders(userRealmRequest);

  return userRealmRequest;
};

/**
 * Set's up the nock expected response for successful UserRealm request responses.
 * @param  {bool} federated Indicates whether the response should indicate a federated or managed tenant.
 * @return {nock}
 */
util.setupExpectedUserRealmResponseCommon = function(federated) {
  var responseDoc;

  if (federated) {
    responseDoc = parameters.userRealmResponseFederated;
  } else {
    responseDoc = parameters.userRealmResponseManaged;
  }

  return util.setupExpectedUserRealmResponse(200, responseDoc, parameters.authority);
};

util.setupExpectedInstanceDiscoveryAndUserRealmRequest = function(federated) {
  var instanceDiscovery = util.setupExpectedInstanceDiscoveryRequestCommon();
  var userRealm = util.setupExpectedUserRealmResponseCommon(federated);

  return {
    done : function() {
      instanceDiscovery.done();
      userRealm.done();
    }
  };
};

util.setupExpectedFailedMexCommon = function() {
  var mexRequest = nock(parameters.adfsUrlNoPath).get(parameters.adfsMexPath).reply(500);

  util.matchStandardRequestHeaders(mexRequest);

  return mexRequest;
};

util.setupExpectedMexCommon = function() {
  var mexDoc = fs.readFileSync(parameters.MexFile, 'utf8');
  var mexRequest = nock(parameters.adfsUrlNoPath).get(parameters.adfsMexPath).reply('200', mexDoc);

  util.matchStandardRequestHeaders(mexRequest);

  return mexRequest;
};

util.setupExpectedWSTrustRequestCommon = function() {
  var RSTRDoc = fs.readFileSync(parameters.RSTRFile, 'utf8');
  var wstrustRequest = nock(parameters.adfsUrlNoPath)
                       .filteringRequestBody(function() {return '*';})
                       .post(parameters.adfsWsTrustPath, '*')
                       .reply(200, RSTRDoc);

  util.matchStandardRequestHeaders(wstrustRequest);

  return wstrustRequest;
};

util.setupExpectedMexWSTrustRequestCommon = function() {
  var expectedMex = util.setupExpectedMexCommon();
  var expectedWsTrust = util.setupExpectedWSTrustRequestCommon();

  var doneFunc = function() {
    expectedMex.done();
    expectedWsTrust.done();
  };

  return { done : doneFunc };
};

util.setupExpectedRefreshTokenRequestResponse = function(httpCode, returnDoc, authorityEndpoint, resource, clientSecret) {
  var authEndpoint = authorityEndpoint || parameters.authority;

  var queryParameters = {};
  queryParameters['grant_type'] = 'refresh_token';
  queryParameters['client_id'] = parameters.clientId;
  if (clientSecret) {
    queryParameters['client_secret'] = clientSecret;
  }
  if (resource) {
    queryParameters['resource'] = resource;
  }
  queryParameters['refresh_token'] = parameters.refreshToken;

  return util.setupExpectedOAuthResponse(queryParameters, parameters.tokenUrlPath, httpCode, returnDoc, authEndpoint);
};

util.setupExpectedClientAssertionTokenRequestResponse = function(httpCode, returnDoc, authorityEndpoint) {
  var authEndpoint = authorityEndpoint || parameters.authority;

  var queryParameters = {};
  queryParameters['grant_type'] = 'client_credentials';
  queryParameters['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  queryParameters['client_assertion'] = parameters.expectedJwt;
  queryParameters['client_id'] = parameters.clientId;
  queryParameters['resource'] = parameters.resource;

  return util.setupExpectedOAuthResponse(queryParameters, parameters.tokenUrlPath, httpCode, returnDoc, authEndpoint);
};

function isDateWithinTolerance(date, expectedDate) {
  var expected = expectedDate || new Date();
  var fiveBefore = expected.clone();
  fiveBefore.addSeconds(-5);
  expected.addSeconds(5);

  if (date.between(fiveBefore, expected)) {
    return true;
  }

  return false;
}

function isExpiresWithinTolerance(expiresOn, expired){
  if (!expiresOn) {
    console.log('no expires_on');
    return false;
  }

  // Add the expected expires_in latency.
  var expectedExpires = expired ? new Date() : Date.yesterday();
  expectedExpires = expiresOn.addSeconds(28800);
  return isDateWithinTolerance(expiresOn, expectedExpires);
}

util.isMatchTokenResponse = function(expected, received, print) {
  var expiresOn = received['expiresOn'];
  var createdOn = received['createdOn'];

  if (print) {
    console.log('DIFFS');
    util.findDiffs(expected, received);
    console.log('EXPECTED');
    console.log(expected);
    console.log('RECEIVED');
    console.log(received);
  }

  if (!(isExpiresWithinTolerance(expiresOn) || isExpiresWithinTolerance(expiresOn, true))) {
    return false;
  }

  if (!isDateWithinTolerance(createdOn)) {
    return false;
  }

  // Compare the expected and responses without the expires_on field as that was validated above.
  var receivedClone = _.clone(received);
  delete receivedClone['expiresOn'];
  delete receivedClone['createdOn'];
  var expectedClone = _.clone(expected);
  delete expectedClone['expiresOn'];
  delete expectedClone['createdOn'];

  if (receivedClone.clientId && !expectedClone.clientId) {
    delete receivedClone.clientId;
  }

  var isEqual = _.isEqual(expectedClone, receivedClone);
  return isEqual;
};

util.isMathDeviceCodeResponse = function(expected, received, print) {
   if (print) {
      console.log('DIFFS');
      util.findDiffs(expected, received);
      console.log('EXPECTED');
      console.log(expected);
      console.log('RECEIVED');
      console.log(received);
   }

   var receivedClone = _.clone(received);
   var expectedClone = _.clone(expected);

   var isEqual = _.isEqual(expectedClone, receivedClone);

   return isEqual;
};

util.createTokenResponseWithIdToken = function(response) {
  response = response || _.clone(parameters.successResponseWithRefresh);
  _.extend(response, parsedIdToken);
  return response;
};

util.isMatchIdTokenResponse = function(expected, received) {
  expected = _.clone(expected);
  _.extend(expected, parsedIdToken);
  return util.isMatchTokenResponse(expected, received);
};

util.createIdTokenServerResponse = function(baseResponse) {
  var sourceResponse = baseResponse || _.clone(parameters.successResponseWithRefresh);
  sourceResponse = _.clone(sourceResponse);
  sourceResponse['id_token'] = encodedIdToken;
  return sourceResponse;
};

util.createEmptyADALObject = function() {
  var context = log.createLogContext();
  var component = 'TEST';
  var logger = new log.Logger(component, context);
  var callContext = { _logContext : context };
  var adalObject = {
    _log : logger,
    _callContext : callContext
  };
  return adalObject;
};

util.findDiffs = function(leftObj, rightObj) {
  var keys = _.keys(leftObj);
  var rightKeys = _.keys(rightObj);
  if (keys.length !== rightKeys.length) {
    console.log('unmatched number of keys.');
  }

  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (leftObj[key] !== rightObj[key]) {
      console.log(key +': ' + leftObj[key] + ' | ' + rightObj[key]);
    }
  }
};

util.clearStaticCache = function() {
  var context = new adal.AuthenticationContext(parameters.authorityTenant);
  var cacheArray = context.cache._entries;

  var entry;
  do {
    entry = cacheArray.pop();
  } while (entry);
};

util.trimPathFromUrl = function(stringUrl) {
  var u = url.parse(stringUrl);
  return url.resolve(u, '/');
};

util.getNockAuthorityHost = function(authority) {
    var authEndpoint = authority || this.commonParameters.evoEndpoint;
    return this.trimPathFromUrl(authEndpoint);
};

module.exports = util;
