import tokenError from '../errors/tokenerror.js';
import internalOAuthError from '../errors/internaloautherror.js';

let tokenErrorObj = Object.create(tokenError);
let oauthError = Object.create(internalOAuthError);

// Create parent OAuth object.
let OAuthEmbassy = {};

/******************* BEGIN EMBASSY AUGMENTATION ***************************
Augment the OAuth object with action functions. These provide properties
and functions that are common to both OAuth 1.0 and 2.0 authentication
protocols, and assist in the exchange of an authorization code for an
access token. The goal of these functions is to negotiate the exchange,
capture the user's profile data, and pass it on to the appropriate callback
in order to successfully log the user into the site.
***************************************************************************/

Object.defineProperties(OAuthEmbassy,
{
  
  /* populateOAuthEmbassy ***
  
    This function grabs the options object and verify callback passed into
    the preliminary `populate` function at the beginning of the delegation
    chain. This populates properties that are common to both OAuth 1.0 and
    2.0 authentication protocol into the initiating emissary. As such, this
    is a protected function and should not be called directly.
    
  */
  _populateOAuthEmbassy:
  {
    value: function populateOAuthEmbassy(options, verify)
    {
      if (typeof options == 'function')
      {
        verify = options;
        options = undefined;
      }
      options = options || {};
      
      if (!verify)
      { throw new TypeError('OAuth2Strategy requires a verify callback'); }
      
      this._verify = verify;
      this._callbackURL = options.callbackURL;
      this._trustProxy = options.proxy;
      this._passReqToCallback = options.passReqToCallback;
      this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _createOAuthError ***
    
    Creates an OAuth error. This function is called by `loaded` at the start
    of the delegation chain by the initiating emissary. This function is
    protected and should not be called directly nor overridden. 
    
    @param {String} message
    @param {Object|Error} err
    @api private
    
  */
  
  _createOAuthError:
  {
    value: function(message, err)
    {
      let e;
      if (err.statusCode && err.data)
      {
        try { e = this.parseErrorResponse(err.data, err.statusCode); }
        catch (_) {}
      }
      if (!e)
      { e = oauthError.build(message, err); }
      return e;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _loadUserProfile ***
  
    Load user profile, contingent upon options. This function is called by
    `loaded` at the start of the delegation chain by the initiating
    emissary. This function is protected and should not be called directly
    nor overridden.
    
    @param {String} accessToken
    @param {Function} done
    @api private
    
  */
  
  _loadUserProfile:
  {
    // For OAuth, object must include token & tokenSecret.
    // For OAuth2, object must include auth code & accessToken.
    value: (args, results, done) =>
    {
      let { protocol, token, tokenSecret, params } = args;
      
      function loadIt()
      {
        if (protocol === 'oauth')
        {
          return args.userProfile(token, tokenSecret, params, done);
        } else if (protocol === 'oauth2') {
          return args.userProfile(results, done);
        }
      }
      
      function skipIt()
      { return done(null); }
      
      function skipUserProfileCB(err, skip)
      {
        if (err)
        { return done(err); }
        if (!skip)
        { return loadIt(); }
        return skipIt();
      }
      
      if (typeof args.skipUserProfile == 'function' && args.skipUserProfile.length > 1)
      {
        if (protocol === 'oauth')
        {
          args.skipUserProfile(token, tokenSecret, skipUserProfileCB);
        } else if (protocol === 'oauth2') {
          args.skipUserProfile(access_token, skipUserProfileCB);
        }
      } else {
        let skip = (typeof args.skipUserProfile == 'function') ? args.skipUserProfile() : args.skipUserProfile;
        if (!skip)
        { return loadIt(); }
        return skipIt();
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* authorizationParams ***
  
    Return extra parameters to be included in the user authorization
    request.
    
    Some OAuth/OAuth2 providers allow additional, non-standard parameters to
    be included when requesting authorization.  Since these parameters are
    not standardized by the OAuth specification, OAuth-based authentication
    strategies can override this function in order to populate these
    parameters as required by the provider.
    
    @param {Object} options
    @return {Object}
    @api protected
    
  */
  
  authorizationParams:
  {
    value: function authParams(options)
    { return {}; },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /* parseErrorResponse ***
  
    Parse error response from OAuth endpoint.
    
    OAuth-based authentication strategies can overrride this function in
    order to parse error responses received from the request token and
    access token endpoints, allowing the most informative message to be
    displayed.
    
    If this function is not overridden, a generic error will be thrown.
    
    @param {String} body
    @param {Number} status
    @return {Error}
    @api protected
    
  */
  
  parseErrorResponse:
  {
    value: function parseErrorResponse(body, status)
    {
      let json = JSON.parse(body);
      if (json.error)
      {
        tokenErrorObj.build(json.error_description, json.error, json.error_uri);
        return tokenErrorObj;
      }
      return null;
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  /* tokenParams ***
  
    Return extra parameters to be included in the request token request.
    
    Some OAuth providers require additional parameters to be included when
    issuing a request token.  Since these parameters are not standardized by
    the OAuth 1.0/2.0 specification, OAuth-specific emissaries ought to
    override this function in order to populate these parameters as required
    by the provider.
    
    @param {Object} options
    @return {Object}
    @api protected
    
  */
  
  tokenParams:
  {
    value: function tokenParams(options)
    { return {}; },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /* userProfile ***
  
    Retrieve user profile from service provider.
   
    OAuth 1.0/2.0-based authentication strategies can overrride this
    function in order to load the user's profile from the service provider.
    This assists applications (and users of those applications) in the
    initial registration process by automatically submitting required
    information.
   
    @param {String} accessToken
    @param {Function} done
    @api protected
    
  */
  
  userProfile:
  {
    value: function(results, done)
    { return done(null, {}); },
    writable: true,
    configurable: true,
    enumerable: true
  }
  

/******************* END EMBASSY AUGMENTATION *****************************/

});

export default OAuthEmbassy;