import url from 'url'; // node
import crypto from 'crypto'; // node
import OAuth2Ambassador from './oauth2ambassador.js';
import { merge, originalURL } from '../utilities/utils.js';

/* Object.create(OAuth2Ambassador) ***

  OAuth2Delegate object construction, delegation, and augmentation.
  
  Upon object creation, augment the OAuth2Embassy object with methods to
  facilitate authentication, gather user information, and load user profile.
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
  
  The OAuth2Delegate object provides a functional layer between the emissary
  and OAuth2/OAuth ambassador objects allowing for ease of integration into
  any Express-related application.

*/

let OAuth2Delegate = Object.create(OAuth2Ambassador,

/* BEGIN DELEGATE AUGMENTATION ******************************************
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
      { throw new TypeError('OAuth2 Delegate requires a verify callback'); }
      if (!options.authorizeURL)
      { throw new TypeError('OAuth2 Delegate requires an authorizeURL'); }
      if (!options.accessTokenURL)
      { throw new TypeError('OAuth2 Delegate requires an accessTokenURL'); }
      if (!options.clientID)
      { throw new TypeError('OAuth2 Delegate requires an clientID'); }
      if (!options.callbackURL)
      { throw new TypeError('OAuth2 Delegate requires an callback URL'); }
    
      this._populateOAuth2Ambassador(options, verify);
      this.name = options.name || 'oauth2';
      this._scopeSeparator = options.scopeSeparator || ' ';
      this._pkceMethod = (options.pkce === true) ? 'S256' : options.pkce;
      this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizeURL).hostname);
      this._stateStore;
      
      if (options.store)
      {
        this._stateStore = options.store;
      } else {
        if (options.state)
        {
          if (options.pkce)
          {
            this._PKCESessionStore.build({ key: this._key });
            this._stateStore = this._PKCESessionStore;
          } else {
            this._stateStore = Object.create(this._OAuth2SessionStore);
            this._stateStore.build({ key: this._key });
          }
        } else {
          if (options.pkce)
          { throw new TypeError('OAuth2Strategy requires `state: true` option when PKCE is enabled'); }
          this._stateStore = this.nullStore();
        }
      }
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
    Express `req` object, establishes and verifies the state parameter and
    then calls `_loaded` when ready.
    
  */
  
  _authenticate:
  {
    value: function authenticate(req)
    {
      let callbackURL = this._callbackURL;
      let parsed = url.parse(callbackURL);
      if (!parsed.protocol)
      {
        /* The callback URL is relative. Therefore, resolve a fully
        qualified URL from the URL of the originating request. */
        callbackURL = url.resolve(originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
      
      if (req.query?.error)
      {
        if (req.query.error === 'access_denied')
        {
          return this.fail({ message: req.query.error_description });
        } else {
          this._authorizationError.build(req.query.error_description, req.query.error, req.query.error_uri);
          return this.error(this._authorizationError);
        }
      }
      
      try
      {
        if (req.query.code)
        {
          let code = req.query.code;
          
          // State debugger //
          console.log('state debugger');
          // console.log(this._stateStore);
          console.log('x-forwarded-proto:', req.headers["x-forwarded-proto"]);
          console.log('protocol:', req.protocol);
          console.log(`${req.session.id}:`);
          console.log(req.session);
          // console.log(this._state);
          debugger;
          
          this._stateStore._verifyState.call(this, req)
          .then(stately =>
          {
            // Promises debugger //
            console.log('Promise resolved: state verified');
            console.log('x-forwarded-proto:', req.headers["x-forwarded-proto"]);
            console.log('protocol:', req.protocol);
            console.log(stately);
            debugger;
            
            let { ok } = stately;
            if (!ok)
            {
              return console.log('NOPE');
            } else {
              this._loaded(req, code);
            }
          })
          .catch(stately =>
          {
            let { err, ok, state } = stately;
            return console.error(err);
          });
        } else {
          this._stateStore._store.call(this, req)
          .then(state =>
          {
            // Promise debugger //
            console.log('Promise resolved from state store')
            // console.log(this._state);
            console.log(req.session.id, ':');
            console.log(req.session);
            debugger;
            
            let verifier, challenge;
            let params = this.authorizationParams();
            params.response_type = 'code';
            params.redirect_uri = callbackURL;
            params.state = req.session[this._key].state;
            
            let scope = this._scope;
            if (scope)
            {
              if (Array.isArray(scope))
              { scope = scope.join(this._scopeSeparator); }
              params.scope = scope;
            }
            
            if (this._pkceMethod)
            {
              verifier = base64url(crypto.pseudoRandomBytes(32))
              switch (this._pkceMethod)
              {
                case 'plain':
                  challenge = verifier;
                  break;
                case 'S256':
                  challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
                  break;
                default:
                  return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
              }
              params.code_challenge = challenge;
              params.code_challenge_method = this._pkceMethod;
            }
            
            let parsedAuthURL = url.parse(this._authorizeURL, true);
            merge(parsedAuthURL.query, params);
            parsedAuthURL.query['client_id'] = this._clientID;
            delete parsedAuthURL.search;
            let location = url.format(parsedAuthURL);
            this.redirect(location);
          }).catch(err => console.error(err));
        }
      } catch(err) {
        console.log('OAuth2Delegate try/catch Error Handler:');
        return console.error(err);
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  _loaded:
  {
    value: function loaded(req, code)
    {
      // TODO: Build Promise series, breaking down functions in
      // OAuth2Ambassador to return required info for OAuth headers
      this.acquireAccessToken(code)
      .then(results =>
      {
        // let params = this.tokenParams(options);
        // params.grant_type = 'authorization_code';
        // if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok == 'string')
        { results.code_verifier = ok; } // PKCE
        
        this.userProfile(results)
        .then(profile => this._loadUserSuccess(req, profile));
      })
      .catch(err => console.error('An error occurred in receiving a Promise from _loadUserProfile:', err));
    },
    writable: false,
    configurable: true,
    enumerable: false
  }
  
/* END DELEGATE AUGMENTATION *******************************************/
  
});

export default OAuth2Delegate;

