import url from 'url'; // node
import OAuth2Emissary from './oauth2emissary.js';
import sessionStore from '../state/oauth2session.js';
import nullStore from '../state/null.js';
import authorizationError from '../errors/authorizationerror.js';

let sessionStateStore = Object.create(sessionStore);
let nullStateStore = Object.create(nullStore);
let authError = Object.create(authorizationError);

/* Object.create(OAuth2Emissary) ***

  OAuth2Embassy object construction, delegation, and augmentation.
  
  Upon object creation, augment the OAuth2Embassy object with methods to
  facilitate authentication, gather user information, and load user profile.
  The delegation chain is as follows:
  
    ambassador > OAuth2Delegate > OAuth2Emissary > OAuthEmbassy
  
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
  
  The OAuth2Embassy object provides a functional layer between ambassador
  and the OAuth2/OAuth objects allowing for ease of integration into any
  Express-related application.

*/

let OAuth2Delegate = Object.create(OAuth2Emissary,

/******************* BEGIN DELEGATE AUGMENTATION ************************
Augment the OAuth2Embassy object with action functions. These functions
provide the interface between the main application and the OAuth2 object
layer which contains the preliminary functions that serve to facilitate
the exchange of an authorization code for an access token. The goal of
these functions is to negotiate the exchange, capture the user's profile
data, and pass it on to the appropriate callback in order to successfully
log the user into the site.
*************************************************************************/

{
  
  /* _populateOAuth2Delegate *

    This takes the given options object and populates the object with the
    relevant properties necessary to facilitate a successfully authorization
    code and access token exchange. As the heavy lifting is done in the
    OAuth2 layer, OAuth2Embassy takes from the options object what it needs
    and passes the rest along by calling the protected `_populateOAuth2`
    function, per the delegation chain. OAuth2Embassy should not be used to
    initiate an authentication request, and thus this `populate` function
    is ptotected and should not be called directly. To authenticate using a
    generic OAuth2 strategy, use the `OAuth2Emissary` emissary.
    
    @param {Object} options
    @param {Function} verify
    @api public
    
  */
  
  _populateOAuth2Delegate:
  {
    value: function populateOAuth2Delegate(options, verify)
    {
      if (typeof options == 'function')
      {
        verify = options;
        options = undefined;
      }
      options = options || {};
    
      if (!verify)
      { throw new TypeError('OAuth2Strategy requires a verify callback'); }
      if (!options.authorizeURL)
      { throw new TypeError('OAuth2Strategy requires an authorizeURL'); }
      if (!options.accessTokenURL)
      { throw new TypeError('OAuth2Strategy requires an accessTokenURL'); }
      if (!options.clientID)
      { throw new TypeError('OAuth2Strategy requires an clientID'); }
    
      this._populateOAuth2Emissary(options, verify);
      this.name = options.name || 'oauth2';
      this._scopeSeparator = options.scopeSeparator || ' ';
      this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizeURL).hostname);
      this._stateStore;
      
      if (options.state)
      {
        sessionStateStore.build({ key: this._key });
        this._stateStore = sessionStateStore;
      } else {
        nullStateStore.build();
        this._stateStore = nullStateStore;
      }
      
      this._trustProxy = options.proxy;
      this._passReqToCallback = options.passReqToCallback || true;
      this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _authenticate ***
    
    This is the function that will be returned by the
    `ambassador.authenticate()` call, which is referenced in the main
    authenticator.js module. The call-stack in this specific case is as
    follows:
      
      `ambassador.authenticate()` calls the framework connectAuth, or
      `authenticate` function, which in turn calls this _authenticate
      function.
      
    As such, this _authenticate function is a protected resource and should 
    not be called directly. This function takes necessary data from the
    Express `req` object and calls `loaded` when ready.
    
  */
  
  _authenticate:
  {
    value: function authenticate(req)
    {
      this._stateStore.store(req);
      let code = req.query.code;
      let state = req.query.state;
      
      if (req.query.error)
      {
        if (req.query.error == 'access_denied')
        {
          return console.error('MESSAGE:', req.query.error_description);
        } else {
          authError.build(req.query.error_description, req.query.error, req.query.error_uri);
          return console.error(authError);
        }
      }
      
      let callbackURL = this._callbackURL;
      
      if (callbackURL)
      {
        let parsed = url.parse(callbackURL);
        if (!parsed.protocol)
        {
          // The callback URL is relative, resolve a fully qualified URL
          // from the URL of the originating request.
          callbackURL = url.resolve(originalURL(req, { proxy: this._trustProxy }), callbackURL);
        }
      }
      
      if (req.query.code)
      {
        let preLoad;
        try
        {
          this._stateStore.verify(req, state, function verifyCB(err, ok, state)
          {
            preLoad = {};
            if (err)
            { preLoad.err = err; }
            preLoad.ok = ok;
            if (state)
            { preLoad.state = state; }
            // console.log(preLoad);
            return preLoad;
          });
          this._loaded(req, code, preLoad);
        } catch (ex) {
          return console.error(ex);
        }
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _loaded:
  {
    value: function loaded(req, code, object)
    {
      let err = object.err;
      let ok = object.ok;
      let state = object.state;
      
      if (err)
      { return console.error(err); }
      if (!ok)
      { return this.fail(state, 403); }
      
      this.getOAuthAccessToken(code, (err, params, results) =>
      {
        let passReqToCallback = this._passReqToCallback;
        let verify = this._verify;
        
        // let params = this.tokenParams(options);
        // params.grant_type = 'authorization_code';
        // if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok == 'string')
        { params.code_verifier = ok; } // PKCE
          
        if (err)
        { return console.error(this._createOAuthError('Failed to obtain access token', err)); }
        
        let passThru =
        {
          protocol: 'oauth2',
          userProfile: this.userProfile,
          skipUserProfile: this._skipUserProfile,
          token: undefined,
          tokenSecret: undefined,
          params: undefined,
        }
        
        this._loadUserProfile(passThru, results, function loadUserProfileDone(err, profile)
        {
          if (err)
          { return console.error(err); }
          
          function verified(err, user, info)
          {
            if (err)
            { return console.error(err); }
            if (!user)
            { return this.fail(info); }
            
            info = info || {};
            if (state)
            { info.state = state; }
            this.success(user, info);
          }
          
          params.access_token = results.access_token;
          params.refresh_token = results.refresh_token;
          params.verified = verified(err, user, info);                    
          
          try
          {
            if (passReqToCallback)
            {
              verify(req, params, profile);
            } else {
              verify({}, params, profile);
            }
          } catch (ex) {
            return console.error(ex);
          }
        });
      });
    },
    writable: false,
    configurable: true,
    enumerable: false
  }
  
/******************* END DELEGATE AUGMENTATION *************************/
  
});

export default OAuth2Delegate;

