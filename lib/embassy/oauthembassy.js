// import STATE Store delegates
import nullStore from '../state/null.js';
import OAuth1SessionStore from '../state/oauth1session.js';
import OAuth2SessionStore from '../state/oauth2session.js';
import PKCESessionStore from '../state/pkcesession.js';

// import ERROR delegates
import authorizationError from '../errors/authorizationerror.js';
import tokenError from '../errors/tokenerror.js';
import internalOAuthError from '../errors/internaloautherror.js';


/* OAuthEmbassy = {} ***

  OAuth 1.0/2.0 base object construction and augmentation.
  
  Upon object creation, augment the OAuthEmbassy object with methods common
  to both OAuth 1.0 & 2.0 protocols, including the acquisition of the user
  object upon successful authentication. This becomes the parent object that
  all OAuth-related authentication ambassadors become linked to.
  The delegation chain is as follows:
  
    ambassador > OAuth1Delegate > OAuth1Emissary > OAuthEmbassy
                              -or-
    ambassador > OAuth2Delegate > OAuth2Emissary > OAuthEmbassy
  
  This object contains more comprehensive error-handling functions that can
  be called where necessary when composing functions to replace those that
  call for additional parameters to be acquired and sent.
  
*/

let OAuthEmbassy = {};

/* BEGIN EMBASSY AUGMENTATION *********************************************
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
      this._passReqToCallback = options.passReqToCallback || true;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _loadUserSuccess ***
    
    Called at the end of the Ambassador's authenticate() call when all
    Promises in the promise chain have been resolved and all errors
    accounted for. `loadUserSuccess` takes the acquired user object and
    sends it to the original verify callback to begin the process of login
    and (de)serialization.
    
  */
  
  _loadUserSuccess:
  {
    value: function loadUserSuccess(req, profile)
    {
      try
      {
        if (this._passReqToCallback)
        {
          console.log('You made it this far:');
          console.log(req.session);
          this._verify(req, profile);
        } else {
          this._verify(null, profile);
        }
      } catch (ex) {
        return console.error(ex);
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* OAUTH STATE STORES ***************************************************
  Setup and provide state when sending credentials. Upon receipt of
  authentication codes or tokens, verify state before requesting the user
  object.
  *************************************************************************/
  
  _nullStore:
  {
    value: Object.create(nullStore),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _OAuth1SessionStore:
  {
    value: Object.create(OAuth1SessionStore),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _OAuth2SessionStore:
  {
    value: Object.create(OAuth2SessionStore),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _PKCESessionStore:
  {
    value: Object.create(PKCESessionStore),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* OAUTH ERROR OBJECTS **************************************************
  Various error objects to specify where the error is occurring, and why.
  *************************************************************************/
  
  _authorizationError:
  {
    value: Object.create(authorizationError),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _internalOAuthError:
  {
    value: Object.create(internalOAuthError),
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _tokenError:
  {
    value: Object.create(tokenError),
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
    value: function createOAuthError(message, err)
    {
      let e;
      try
      {
        if (err.statusCode && err.data)
        { e = this._parseErrorResponse(err.data, err.statusCode); }
        if (!e)
        { e = this._internalOAuthError.build(message, err); }
        return e;
      } catch(error) {
        console.log('Failed to create error response at _createOAuthError:');
        return console.error(error);
      }
      
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _parseErrorResponse ***
  
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
  
  _parseErrorResponse:
  {
    value: function parseErrorResponse(body, status)
    {
      let json = JSON.parse(body);
      if (json.error)
      {
        this._tokenError.build(json.error_description, json.error, json.error_uri);
        return this._tokenError;
      }
      return null;
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  /* OAUTH PARAMETER & PROFILE LOADING ************************************
  Some OAuth providers ask for additional parameters when fetching
  authorization codes, access tokens, and the user objects. These functions
  can be overriden to provide the provider with the necessary information to
  successful authenticate and acquire the user object.
  *************************************************************************/
  
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
    value: function authorizationParams(options)
    { return {}; },
    writable: false,
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
    @api protected
    
  */
  
  userProfile:
  {
    value: function(results)
    { return Promise.resolve({}); },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  /* verified ***
    
    Function to call if no custom login and (de)serialization sequence is
    established in the verify callback. This function can be overridden as
    necessary.
    
  */
  
  verified:
  {
    value: function verified(user, info)
    {
      if (!user)
      { return this.fail(info); }
      
      info = info || {};
      // if (state)
      // { info.state = state; }
      this.success(user, info);
    },
    writable: true,
    configurable: true,
    enumerable: true
  }
  

/* END EMBASSY AUGMENTATION ***********************************************/

});

export default OAuthEmbassy;