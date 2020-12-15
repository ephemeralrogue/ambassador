// TODO: break request function into a series of Promise-based functions
// that run asynchronously to prepare headers for authentication token or
// code retrieval. Promise.all() to capture results, bundle the info then
// send the POST request in _executeRequest.

import querystring from 'querystring';
import http from 'http';
import https from 'https';
import URL from 'url';
import OAuthEmbassy from './oauthembassy.js';

/* Object.create(OAuthEmbassy) ***

  OAuth2 object construction, delegation, and augmentation.
  
  Upon object creation, augment the OAuth2 object with methods to facilitate
  authentication, gather user information, and load user profile.
  The delegation chain is as follows:
  
    emissary > OAuth2Delegate > OAuth2Ambassador > OAuthEmbassy
  
  The OAuth parent object contains properties and methods that are common to
  both OAuth 1.0 and 2.0 authentication protocols. The OAuth2Embassy
  authenticates requests using the OAuth 2.0 framework.
  
  OAuth 2.0 provides a facility for delegated authentication, whereby users
  can authenticate using a third-party service such as Facebook.  Delegating
  in this manner involves a sequence of events, including redirecting the
  user to the third-party service for authorization. Once authorization
  has been granted, the user is redirected back to the application and an
  authorization code is given and exchanged for an access token. The access
  token is then used to obtain the user object from the authorizing service.
  
  The OAuth2 object contains all of the necessary components to handle
  authentication via the OAuth 2.0 protocol.
  
*/

const OAuth2Ambassador = Object.create(OAuthEmbassy,

/* BEGIN AMBASSADOR AUGMENTATION ******************************************
Augment the OAuth2 object with action functions. These provide properties
and functions that manage application authentication and the acquisition of
the user object, first assisting in the exchange of an authorization code
for an access token, then sending the request for the user resource. The
goal of these functions is to negotiate the exchange, capture the user's
profile data, and pass it on to the appropriate callback in order to
successfully log the user into the site.
***************************************************************************/

{
  /* _populateOAuth2Ambassador ***
    
    This function takes an options object passed from OAuth2Embassy and
    populates either the ambassador or embassy object with the information
    necessary to successfully authenticate a request. As such, this is a
    protected function and should not be called directly.
   
  */
   
  _populateOAuth2Ambassador:
  {
    value: function populateOAuth2Ambassador(options, verify)
    {
      this._populateOAuthEmbassy(options, verify);
      this._clientID = options.clientID;
      this._clientSecret = options.clientSecret;
      this._authorizeURL = options.authorizeURL;
      this._accessTokenURL = options.accessTokenURL;
      this._accessTokenName = "access_token";
      this._authMethod = "Bearer";
      this._customHeaders = {};
      this._useAuthorizationHeaderForGET = false;
      this._scope = options.scope;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _chooseHTTPLibrary:
  {
    value: function chooseHTTPLibrary(parsedUrl)
    {
      let HTTPLibrary = https;
      // As this is OAUth2, we *assume* https unless told explicitly otherwise.
      if (parsedUrl.protocol != "https:")
      { HTTPLibrary = http; }
      return HTTPLibrary;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _getAccessTokenURL:
  {
    value: function getAccessTokenURL()
    { return this._accessTokenURL; },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _getAuthorizeURL:
  {
    value: function getauthorizeURL(params)
    {
      // let params = params || {};
      params['client_id'] = this._clientID;
      return this._authorizeURL + "?" + querystring.stringify(params);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _request:
  {
    value: function request(requestOptions)
    {
      let { method, url, headers, postBody, access_token, p } = requestOptions;
      // console.log(p);
      let parsedUrl = URL.parse(url, true);
      if (parsedUrl.protocol == "https:" && !parsedUrl.port)
      { parsedUrl.port = 443; }
      
      let HTTPLibrary = this._chooseHTTPLibrary(parsedUrl);
    
      let realHeaders = {};
      for (let key in this._customHeaders)
      { realHeaders[key] = this._customHeaders[key]; }
      
      if (headers)
      {
        for (let key in headers)
        { realHeaders[key] = headers[key]; }
      }
      realHeaders['Host'] = parsedUrl.host;
    
      if (!realHeaders['User-Agent'])
      { realHeaders['User-Agent'] = 'ambassador'; }
    
      if (postBody)
      {
        if (Buffer.isBuffer(postBody))
        {
          realHeaders["Content-Length"] = postBody.length;
        } else {
          realHeaders["Content-Length"] = Buffer.byteLength(postBody);
        }
      } else {
        realHeaders["Content-length"] = 0;
      }
      
      if (access_token && !('Authorization' in realHeaders))
      {
        if (!parsedUrl.query)
        { parsedUrl.query = {}; }
        parsedUrl.query[this._accessTokenName] = access_token;
      }
      
      let queryStr = querystring.stringify(parsedUrl.query);
      if (queryStr)
      { queryStr =  "?" + queryStr; }
      
      let options =
      {
        host: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.pathname + queryStr,
        method: method,
        headers: realHeaders,
      }
      
      return new Promise((resolve, reject) =>
      {
        // Some hosts *cough* google appear to close the connection
        // early / send no content-length header allow this behaviour.
        let allowEarlyClose = function isAnEarlyCloseHost(options)
        { return host && host.match(".*google(apis)?.com$"); }
        
        let request = HTTPLibrary.request(options);
        request.on('response', (response) =>
        {
          let result;
          response.on("data", (chunk) =>
          { result+= chunk; });
          response.on("close", function (err)
          {
            if(allowEarlyClose)
            { resolve(result); }
          });
          response.addListener("end", () =>
          {
            resolve(result);
          });
        });
        request.on('error', (err) =>
        {
          reject(err);
        });
      
        if ((options.method === 'POST' || options.method === 'PUT') && postBody)
        { request.write(postBody); }
        request.end();
      }); // end Promise
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _successfulRequest:
  {
    value: function successfulRequest(result)
    {
      let results;
      if (result.startsWith('undefined'))
      {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07, responses
        // should be in JSON. However both Facebook + Github currently use rev05
        // of the spec and neither seem to specify a content-type correctly in
        // their response headers. Also, data returned from Discord will not
        // parse into a usable object. So we chop it up to make it work.
        
        let slicedUp = result.slice(9);
        results = JSON.parse(slicedUp);
      } else {
        results = JSON.parse(result);
      }
      results.protocol = 'oauth2';
      return results;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  acquireAccessToken:
  {
    value: function acquireAccessToken(code)
    {
      let params =
      {
        'client_id': this._clientID,
        'client_secret': this._clientSecret,
        'grant_type': 'authorization_code',
        'redirect_uri': this._callbackURL,
        'scope': this._scope,
        'code': code
      }
      
      params.code = (params.grant_type === 'refresh_token') ? 'refresh_token' : code;
      let postDATA = querystring.stringify(params);
      let postHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' }
      
      let requestOptions =
      {
        method: "POST",
        url: this._accessTokenURL,
        headers: postHeaders,
        postBody: postDATA,
        access_token: null,
        params: params,
        p: 'token'
      }
      
      return new Promise((resolve, reject) =>
      {
        this._request(requestOptions)
        .then(result =>
        {
          // Promise debugger //
          console.log('Access Token Request Promise resolved:');
          console.log(result);
          debugger;
          
          return this._successfulRequest(result);
        })
        .then(results =>
        {
          // Promise debugger //
          console.log('Access Token Request Success Promise resolved:');
          console.log(results);
          debugger;
          
          resolve(results);
        })
        .catch(err =>
        {
          console.log('Error acquiring access token:');
          return console.error(err);
        });
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  acquireUserProfile:
  {
    value: function acquireUserProfile(url, results)
    {
      let { access_token, token_type } = results;
      let GETHeaders;
      if (this._useAuthorizationHeaderForGET === true)
      {
        GETHeaders = { 'Authorization': this.buildAuthHeader(access_token) }
        // access_token = null;
      } else {
        GETHeaders = {
          'Authorization': `${token_type} ${access_token}`
        }
      }
      
      let requestOptions =
      {
        method: "GET",
        url: url,
        headers: GETHeaders,
        postBody: null,
        access_token: access_token,
        p: 'profile'
      }
      
      return new Promise((resolve, reject) =>
      {
        this._request(requestOptions)
        .then(result =>
        {
          // Promise debugger //
          console.log('User Profile Request Promise resolved:');
          console.log(result);
          debugger;
          
          return this._successfulRequest(result)
        })
        .then(results =>
        {
          // Promise debugger //
          console.log('User Profile Request Success Promise resolved:');
          console.log(results);
          debugger;
          
          let profile = results;
          resolve(profile);
        })
        .catch(err =>
        {
          console.log('Error acquiring user profile:');
          return console.error(err);
        });
      });
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  buildAuthHeader:
  {
    value: function buildAuthHeader(token)
    { return `${this._authMethod} ${token}`; },
    writable: false,
    configurable: true,
    enumerable: true
  },

  setAccessTokenName:
  {
    value: function setAccessTokenName(name)
    { this._accessTokenName = name; },
    writable: false,
    configurable: true,
    enumerable: true
  },

  setAuthMethod:
  {
    value: function setAuthMethod(authMethod)
    { this._authMethod = authMethod; },
    writable: false,
    configurable: true,
    enumerable: true
  },

  useAuthorizationHeaderforGET:
  {
    value: function useAuthHeaderForGET(useIt)
    { this._useAuthorizationHeaderForGET = useIt; },
    writable: false,
    configurable: true,
    enumerable: true
  }

/* END AMBASSADOR AUGMENTATION ********************************************/

});

export default OAuth2Ambassador;