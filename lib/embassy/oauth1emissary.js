import crypto from 'crypto';
import http from 'http';
import https from 'https';
import URL from 'url';
import querystring from 'querystring';
import sha1 from './sha1.js';
import OAuthEmbassy from './oauthembassy.js';

const OAuth1Emissary = Object.create(OAuthEmbassy,
{
  
  /* buildOAuth
   * 
   * This function takes an options object with the information necessary
   * to successfully authenticate a request. The options object should
   * should include all of the following:
   *   requestURL
   *   accessURL
   *   consumerKey
   *   consumerSecret
   *   version
   *   signatureMethod
   *   authorizeCallback
   *   nonceSize, optional
   *   customHeaders, optional
   */
   
  populateOAuth1Emissary:
  {
    value: function populateOAuth1Emissary(options)
    {
      this._isEcho = false;
      this._requestURL = options.requestURL;
      this._accessURL = options.accessURL;
      this._consumerKey = options.consumerKey;
      this._consumerSecret= this._encodeData(options.consumerSecret);
      this._version = options.version;
      
      if (options.signatureMethod === "RSA-SHA1")
      { this._privateKey = options.consumerSecret; }
      
      if(options.authorizeCallback === undefined)
      {
        this._authorizeCallback = "oob";
      } else {
        this._authorizeCallback = options.authorizeCallback;
      }
    
      if (options.signatureMethod !== "PLAINTEXT" && options.signatureMethod !== "HMAC-SHA1" && options.signatureMethod !== "RSA-SHA1")
      { throw new Error("Un-supported signature method: " + signatureMethod ); }
      
      this._signatureMethod = options.signatureMethod;
      this._nonceSize = options.nonceSize || 32;
      this._headers = options.customHeaders ||
      {
        "Accept" : "*/*",
        "Connection" : "close",
        "User-Agent" : "Node authentication"
      }
      this._clientOptions = this._defaultClientOptions =
      {
        "requestTokenHttpMethod": "POST",
        "accessTokenHttpMethod": "POST",
        "followRedirects": true
      }
      this._oauthParameterSeperator = ",";
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /* buildEcho
   * 
   * This function takes an options object with the information necessary
   * to successfully authenticate a request. The options object should
   * should include all of the following:
   *   realm
   *   verifyCreds
   *   consumerKey
   *   consumerSecret
   *   version
   *   signatureMethod
   *   nonceSize, optional
   *   customHeaders, optional
   */
  
  buildEcho:
  {
    value: function buildEcho(options)
    {
      this._isEcho = true;
    
      this._realm = options.realm;
      this._verifyCredentials = options.verifyCreds;
      this._consumerKey = options.consumerKey;
      this._consumerSecret = this._encodeData(options.consumerSecret);
      
      if (signatureMethod === "RSA-SHA1")
      { this._privateKey = options.consumerSecret; }
      
      this._version = options.version;
    
      if (options.signatureMethod != "PLAINTEXT" && options.signatureMethod != "HMAC-SHA1" && options.signatureMethod != "RSA-SHA1")
      { throw new Error(`Un-supported signature method: ${options.signatureMethod}`); }
      
      this._signatureMethod = options.signatureMethod;
      this._nonceSize = options.nonceSize || 32;
      this._headers = options.customHeaders ||
      {
        "Accept" : "*/*",
        "Connection" : "close",
        "User-Agent" : "Node authentication"
      }
      
      this._oauthParameterSeperator = ",";
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  nonceChars:
  {
    value:
    [
      'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
      'q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F',
      'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V',
      'W','X','Y','Z','0','1','2','3','4','5','6','7','8','9'
    ],
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  _buildAuthorizationHeader:
  {
    value: function buildAuthorizationHeader(params)
    {
      var authHeader = "OAuth";
      if (this._isEcho) {
        authHeader += 'realm="' + this._realm + '",';
      }
      
      params.reduce((acc, cur, i) =>
      {
        /* While all the parameters should be included within the signature, only the oauth_ arguments 
         * should appear within the authorization header.
         */
        if (this._isParamAnOAuthParam(params[i][0]))
        { authHeader += `${this._encodeData(params[i][0])}="${this._encodeData(params[i][1])}"${this._oauthParameterSeperator}`; }
      }, authHeader);
      
      for(let i= 0; i < params.length; i++) {
         if (this._isParamAnOAuthParam(params[i][0])) {
           authHeader += ` ${this._encodeData(params[i][0])} ="${this._encodeData(params[i][1])}"${this._oauthParameterSeperator}`;
         }
      }
      
      authHeader = authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
      return authHeader;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _createClient:
  {
    value: function createClient(port, hostname, method, path, headers, sslEnabled)
    {
      let options =
      {
        host: hostname,
        port: port,
        path: path,
        method: method,
        headers: headers
      }
      let httpModel;
      if (sslEnabled)
      {
        httpModel = https;
      } else {
        httpModel = http;
      }
      return httpModel.request(options);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _createSignature:
  {
    value: function createSignature(signatureBase, tokenSecret)
    {
      if (tokenSecret === undefined)
      {
        let tokenSecret= "";
      } else {
        tokenSecret = this._encodeData(tokenSecret);
      }
       
      // consumerSecret is already encoded
      let key = `${this._consumerSecret} & ${tokenSecret}`;
      
      let hash = '';
      if (this._signatureMethod === "PLAINTEXT")
      {
        hash = key;
      } else if (this._signatureMethod === "RSA-SHA1") {
        key = this._privateKey || "";
        hash = crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
      } else {
        if (crypto.Hmac)
        {
          hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
        } else {
          hash = sha1(key, signatureBase);
        }
      }
      return hash;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _createSignatureBase:
  {
    value: function createSignatureBase(method, URL, parameters)
    {
      URL = this._encodeData(this._normalizeURL(URL));
      parameters = this._encodeData(parameters);
      return `${method.toUpperCase()} & ${URL} & ${parameters}`;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _decodeData:
  {
    value: function decodeData(toDecode)
    {
      if (toDecode != null)
      { toDecode = toDecode.replace(/\+/g, " "); }
      return decodeURIComponent(toDecode);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _encodeData:
  {
    value: function(toEncode)
    {
      if (toEncode == null || toEncode == "")
      {
        return "";
      } else {
        var result = encodeURIComponent(toEncode);
        /* fix the mismatch between OAuth's RFC3986's and Javascript's beliefs in what is right and wrong */
        return result.replace(/\!/g, "%21")
                     .replace(/\'/g, "%27")
                     .replace(/\(/g, "%28")
                     .replace(/\)/g, "%29")
                     .replace(/\*/g, "%2A");
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _getNonce:
  {
    value: function getNonce(nonceSize)
    {
      let result = [];
      let chars = this.nonceChars;
      let charPos;
      let nonceCharsLength = chars.length;
      
      for (var i = 0; i < nonceSize; i++)
      {
        charPos = Math.floor(Math.random() * nonceCharsLength);
        result[i] =  chars[char_pos];
      }
      return result.join('');
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _getSignature:
  {
    value: function getSignature(method, URL, parameters, tokenSecret)
    {
      let signatureBase = this._createSignatureBase(method, URL, parameters);
      return this._createSignature(signatureBase, tokenSecret);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _getTimestamps:
  {
    value: function getTimestamps()
    { return Math.floor((new Date()).getTime() / 1000); },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _isParamNameOAuthParam:
  {
    value: function isParamNameOAuthParam(parameter)
    {
      let m = parameter.match('^oauth_');
      if(m && (m[0] === "oauth_"))
      {
        return true;
      } else {
        return false;
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /****
  Takes an object literal that represents the arguments, and returns an array
   * of argument/value pairs.
   */
   
  _makeArrayOfArgsHash:
  {
    value: function makeArrayOfArgsHash(argumentsHash)
    {
      let argument_pairs= [];
      for(let key in argumentsHash )
      {
        if (argumentsHash.hasOwnProperty(key))
        {
          let value= argumentsHash[key];
          if( Array.isArray(value) )
          {
            for(var i=0;i<value.length;i++)
            {
              argument_pairs[argument_pairs.length]= [key, value[i]];
            }
          } else {
            argument_pairs[argument_pairs.length]= [key, value];
          }
        }
      }
      return argument_pairs;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _normalizeRequestParams:
  {
    value: function normalizeRequestParams(args)
    {
      let argument_pairs = this._makeArrayOfArgsHash(args);
      // First encode them #3.4.1.3.2 .1
      for (let i = 0; i < argument_pairs.length; i++)
      {
        argument_pairs[i][0]= this._encodeData(argument_pairs[i][0]);
        argument_pairs[i][1]= this._encodeData(argument_pairs[i][1]);
      }
    
      // Then sort them #3.4.1.3.2 .2
      argument_pairs = this._sortRequestParams(argument_pairs);
    
      // Then concatenate together #3.4.1.3.2 .3 & .4
      args = "";
      for (let i = 0; i < argument_pairs.length; i++)
      {
        args += `${argument_pairs[i][0]} = ${argument_pairs[i][1]}`;
        if (i < argument_pairs.length - 1)
        { args += "&"; }
      }
      return args;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _normalizeURL:
  {
    value: function normalizeURL(URL)
    {
      let parsedURL= URL.parse(URL, true)
      let port = "";
      if (parsedURL.port)
      {
        if ((parsedURL.protocol == "http:" && parsedURL.port != "80") ||
            (parsedURL.protocol == "https:" && parsedURL.port != "443"))
        { port= ":" + parsedURL.port; }
      }
    
      if(!parsedURL.pathname  || parsedURL.pathname == "")
      { parsedURL.pathname ="/"; }    
    
      return parsedURL.protocol + "//" + parsedURL.hostname + port + parsedURL.pathname;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _performSecureRequest:
  {
    value: function performSecureRequest(oauth_token, oauth_token_secret, method, URL, extra_params, post_body, post_content_type, callback)
    {
      let params = this._prepareParameters(oauth_token, oauth_token_secret, method, URL, extra_params);
    
      if(!post_content_type)
      { post_content_type= "application/x-www-form-URLencoded"; }
      
      let parsedURL= URL.parse(URL, false);
      if (parsedURL.protocol == "http:" && !parsedURL.port)
      { parsedURL.port= 80; }
      
      if (parsedURL.protocol == "https:" && !parsedURL.port)
      { parsedURL.port= 443; }
    
      let headers = {};
      let authorization = this._buildAuthorizationHeaders(params);
      if (this._isEcho)
      {
        headers["X-Verify-Credentials-Authorization"] = authorization;
      } else {
        headers["Authorization"]= authorization;
      }
    
      headers["Host"] = parsedURL.host
    
      for (let key in this._headers)
      {
        if (this._headers.hasOwnProperty(key))
        { headers[key] = this._headers[key]; }
      }
    
      // Filter out any passed extra_params that are really to do with OAuth
      for (var key in extra_params)
      {
        if (this._isParamAnOAuthParam(key))
        { delete extra_params[key]; }
      }
    
      if ((method == "POST" || method == "PUT") && (post_body == null && extra_params != null))
      {
        // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
        post_body = querystring.stringify(extra_params)
                           .replace(/\!/g, "%21")
                           .replace(/\'/g, "%27")
                           .replace(/\(/g, "%28")
                           .replace(/\)/g, "%29")
                           .replace(/\*/g, "%2A");
      }
    
      if (post_body)
      {
        if (Buffer.isBuffer(post_body))
        {
          headers["Content-length"] = post_body.length;
        } else {
          headers["Content-length"] = Buffer.byteLength(post_body);
        }
      } else {
        headers["Content-length"] = 0;
      }
    
      headers["Content-Type"] = post_content_type;
    
      let path;
      if (!parsedURL.pathname  || parsedURL.pathname == "")
      { parsedURL.pathname ="/"; }
      
      if (parsedURL.query)
      {
        path = `${parsedURL.pathname}?${parsedURL.query}`;
      } else {
        path = parsedURL.pathname;
      }
    
      let request;
      if (parsedURL.protocol == "https:")
      {
        request = this._createClient(parsedURL.port, parsedURL.hostname, method, path, headers, true);
      } else {
        request = this._createClient(parsedURL.port, parsedURL.hostname, method, path, headers);
      }
    
      let clientOptions = this._clientOptions;
      if (callback)
      {
        let data="";
    
        // Some hosts *cough* google appear to close the connection
        // early / send no content-length header. Allow this behaviour.
        let earlyCloseHost = parsedURL.hostName;
        let allowEarlyClose = function isAnEarlyCloseHost(earlyCloseHost)
        {
          return hostName && hostName.match(".*google(apis)?.com$");
        }
        let callbackCalled = false;
        let passBackControl = function passBackControl(response)
        {
          if (!callbackCalled)
          {
            callbackCalled = true;
            if (response.statusCode >= 200 && response.statusCode <= 299)
            {
              callback(null, data, response);
            } else {
              // Follow 301 or 302 redirects with Location HTTP header
              if ((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location)
              {
                this._performSecureRequest(oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type,  callback);
              } else {
                callback({ statusCode: response.statusCode, data: data }, data, response);
              }
            }
          }
        }
    
        request.on('response', (response) =>
        {
          response.setEncoding('utf8');
          response.on('data', (chunk) =>
          { data+=chunk; });
          response.on('end', () =>
          { passBackControl(response); });
          response.on('close', () =>
          {
            if (allowEarlyClose)
            { passBackControl(response); }
          });
        });
    
        request.on("error", (err) =>
        {
          if (!callbackCalled)
          {
            callbackCalled = true;
            callback(err);
          }
        });
    
        if ((method == "POST" || method =="PUT") && post_body != null && post_body != "")
        { request.write(post_body); }
        request.end();
      } else {
        if ((method == "POST" || method =="PUT") && post_body != null && post_body != "")
        { request.write(post_body); }
        return request;
      }
      return;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _prepareParameters:
  {
    value: function prepareParameters(oauth_token, oauth_token_secret, method, URL, extra_params)
    {
      let oauthParameters =
      {
        "oauth_timestamp": this._getTimestamp(),
        "oauth_nonce": this._getNonce(this._nonceSize),
        "oauth_version": this._version,
        "oauth_signature_method": this._signatureMethod,
        "oauth_consumer_key": this._consumerKey
      }
    
      if (oauth_token)
      { oauthParameters["oauth_token"] = oauth_token; }
    
      let sig;
      if (this._isEcho)
      {
        sig = this._getSignature("GET", this._verifyCredentials, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
      } else {
        if (extra_params)
        {
          for (let key in extra_params)
          {
            if (extra_params.hasOwnProperty(key))
            { oauthParameters[key] = extra_params[key]; }
          }
        }
        let parsedURL = URL.parse(URL, false);
    
        if (parsedURL.query)
        {
          let key2;
          let extraParameters = querystring.parse(parsedURL.query);
          for (let key in extraParameters)
          {
            let value = extraParameters[key];
              if (typeof value == "object")
              {
                // TODO: This probably should be recursive
                for (key2 in value)
                { oauthParameters[`${key}[${key2}]`] = value[key2]; }
              } else {
                oauthParameters[key] = value;
              }
          }
        }
        
        sig = this._getSignature(method, URL, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
      }
    
      let params = this._sortRequestParams(this._makeArrayOfArgsHash(oauthParameters));
      params[params.length] = ["oauth_signature", sig];
      return params;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _putOrPost:
  {
    value: function putOrPost(method, URL, oauth_token, oauth_token_secret, post_body, post_content_type, callback)
    {
      let extra_params = null;
      if (typeof post_content_type == "function")
      {
        callback = post_content_type;
        post_content_type = null;
      }
      
      if (typeof post_body != "string" && !Buffer.isBuffer(post_body))
      {
        post_content_type = "application/x-www-form-URLencoded";
        extra_params = post_body;
        post_body = null;
      }
      
      return this._performSecureRequest(oauth_token, oauth_token_secret, method, URL, extra_params, post_body, post_content_type, callback);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  // Sorts the encoded key value pairs by encoded name, then encoded value
  _sortRequestParams:
  {
    value: function sortRequestParams(argument_pairs)
    {
      // Sort by name, then value.
      argument_pairs.sort(function(a,b)
      {
        if (a[0] === b[0]) {
          return a[1] < b[1] ? -1 : 1;
        } else {
          return a[0] < b[0] ? -1 : 1;
        }
      });
      
      return argument_pairs;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  authHeader:
  {
    value: function authHeader(URL, oauth_token, oauth_token_secret, method)
    {
      if (method === undefined)
      { let method = "GET"; }
      
      let params = this._prepareParameters(oauth_token, oauth_token_secret, method, URL, {});
      return this._buildAuthorizationHeaders(params);
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  get:
  {
    value: function get(URL, oauth_token, oauth_token_secret, callback)
    { return this._performSecureRequest(oauth_token, oauth_token_secret, "GET", URL, null, "", null, callback); },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  getOAuthAccessToken:
  {
    value: function getOAuthAccessToken(oauth_token, oauth_token_secret, oauth_verifier,  callback)
    {
      let extraParams = {};
      if (typeof oauth_verifier == "function")
      {
        callback = oauth_verifier;
      } else {
        extraParams.oauth_verifier = oauth_verifier;
      }
    
      this._performSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessURL, extraParams, null, null, function(error, data, response)
      {
        if (error)
        {
          callback(error);
        } else {
          let results = querystring.parse(data);
          let oauth_access_token = results["oauth_token"];
          delete results["oauth_token"];
          let oauth_access_token_secret = results["oauth_token_secret"];
          delete results["oauth_token_secret"];
          callback(null, oauth_access_token, oauth_access_token_secret, results);
         }
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /****
  Gets a request token from the OAuth provider and passes that information
  back to the calling code. The callback should expect a function of the
  following form:
  
    function(err, token, token_secret, parsedQueryString) {}
  
  This method has optional parameters so can be called in the following 2
  ways:
  
  1) Primary use case: Does a basic request with no extra parameters
     getOAuthRequestToken( callbackFunction )
  
  2) As above but allows for provision of extra parameters to be sent as
  part of the query to the server.
     getOAuthRequestToken( extraParams, callbackFunction )
  
  N.B. This method will HTTP POST verbs by default, if you wish to override
  this behaviour you will need to provide a requestTokenHttpMethod option
  when creating the client.
  *****/
   
  getOAuthRequestToken:
  {
    value: function getOAuthRequestToken(extraParams, callback)
    {
      if (typeof extraParams == "function")
      {
        callback = extraParams;
        extraParams = {};
      }
      // Callbacks are 1.0A related
      if (this._authorizeCallback)
      { extraParams["oauth_callback"] = this._authorizeCallback; }
      
      this._performSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestURL, extraParams, null, null, function(error, data, response)
      {
        if (error)
        {
          callback(error);
        } else {
          let results = querystring.parse(data);
    
          let oauth_token = results["oauth_token"];
          let oauth_token_secret = results["oauth_token_secret"];
          delete results["oauth_token"];
          delete results["oauth_token_secret"];
          callback(null, oauth_token, oauth_token_secret, results);
        }
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  // deprecated?
  getProtectedResource:
  {
    value: function getProtectedResource(URL, method, oauth_token, oauth_token_secret, callback)
    { this._performSecureRequest(oauth_token, oauth_token_secret, method, URL, null, "", null, callback); },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  post:
  {
    value: function post(URL, oauth_token, oauth_token_secret, post_body, post_content_type, callback)
    { return this._putOrPost("POST", URL, oauth_token, oauth_token_secret, post_body, post_content_type, callback); },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  put:
  {
    value: function put(URL, oauth_token, oauth_token_secret, post_body, post_content_type, callback)
    { return this._putOrPost("PUT", URL, oauth_token, oauth_token_secret, post_body, post_content_type, callback); },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  remove:
  {
    value: function remove(URL, oauth_token, oauth_token_secret, callback)
    { return this._performSecureRequest(oauth_token, oauth_token_secret, "DELETE", URL, null, "", null, callback); },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  setClientOptions:
  {
    value: function setClientOptions(options)
    {
      let key;
      let mergedOptions = {};
      let hasOwnProperty = Object.prototype.hasOwnProperty;
    
      for (key in this._defaultClientOptions)
      {
        if (!hasOwnProperty.call(options, key))
        {
          mergedOptions[key] = this._defaultClientOptions[key];
        } else {
          mergedOptions[key] = options[key];
        }
      }
    
      this._clientOptions = mergedOptions;
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  signURL:
  {
    value: function signURL(URL, oauth_token, oauth_token_secret, method)
    {
      if (method === undefined)
      { let method = "GET"; }
    
      let params = this._prepareParameters(oauth_token, oauth_token_secret, method, URL, {});
      let parsedURL = URL.parse(URL, false);
    
      let query = "";
      for (let i= 0 ; i < params.length; i++)
      { query += `${params[i][0]}=${this._encodeData(params[i][1])}&`; }
      query = query.substring(0, query.length-1);
    
      return parsedURL.protocol + "//"+ parsedURL.host + parsedURL.pathname + "?" + query;
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
});

export default OAuth1;