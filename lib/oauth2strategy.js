import url from 'url'; // node
import emissary from '@nonsensecodes/emissary';
import { merge, originalURL } from './utilities/utils.js';
import sessionStore from './state/session.js';
import { nullStore } from './state/null.js';
import { authorizationError } from './errors/authorizationerror.js';
import { tokenError } from './errors/tokenerror.js';
import { internalOAuthError } from './errors/internaloautherror.js';

let sessionStateStore = Object.create(sessionStore);
let nullStateStore = Object.create(nullStore);

let authError = Object.create(authorizationError);
let tokenErrorObj = Object.create(tokenError);
let oauthError = Object.create(internalOAuthError);

/* Object construction. Import OAuth2 object from Emissary dependency
 * and use Emissary as base object to which OAuth2Strategy can delegate.
 * Upon object creation, augment OAuth2Strategy with methods to facilitate
 * authentication, gather user information, and load user profile.
 * 
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2Strategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

let OAuth2Strategy = Object.create(emissary, {
  
  // ----- BEGIN STRATEGY AUGMENTATION -----
  // Augment the new strategy instance with action functions. These functions
  // serve to facilitate the exchange of an authorization code for an access token.
  // The goal of these functions is to negotiate the exchange, capture the user's
  // profile data, and pass it on to the appropriate callback in order to successfully
  // log the user into the site.
  
  /* build
   * 
   * This takes the given options object and populates the strategy with the necessary
   * information to facilitate a successfully authorization code and access token
   * exchange.
   */
  
  build: {
    value: function populateOAuth2(options, verify) {
      if (typeof options == 'function') {
        verify = options;
        options = undefined;
      }
      options = options || {};
    
      if (!verify) { throw new TypeError('OAuth2Strategy requires a verify callback'); }
      if (!options.authorizeURL) { throw new TypeError('OAuth2Strategy requires an authorizeURL'); }
      if (!options.accessTokenURL) { throw new TypeError('OAuth2Strategy requires an accessTokenURL'); }
      if (!options.clientID) { throw new TypeError('OAuth2Strategy requires an clientID'); }
    
      this.buildOAuth2(options);
      this.name = 'oauth2';
      
      this._verify = verify;
      this._scope = options.scope;
      this._scopeSeparator = options.scopeSeparator || ' ';
      this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizeURL).hostname);
      this._stateStore;
      
      if (options.state) {
        sessionStateStore.build({ key: this._key });
        this._stateStore = sessionStateStore;
      } else {
        nullStateStore.build();
        this._stateStore = nullStateStore;
      }
      
      // this._trustProxy = options.proxy;
      this._passReqToCallback = options.passReqToCallback || true;
      this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  
  
  _createOAuthError: {
    value: function(message, err) {
      var e;
      if (err.statusCode && err.data) {
        try {
          e = this.parseErrorResponse(err.data, err.statusCode);
        } catch (_) {}
      }
      if (!e) {
        e = oauthError.build(message, err);
      }
      return e;
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /**
   * Retrieve user profile from service provider.
   *
   * OAuth 2.0-based authentication strategies can overrride this function in
   * order to load the user's profile from the service provider.  This assists
   * applications (and users of those applications) in the initial registration
   * process by automatically submitting required information.
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api protected
   */
  
  userProfile: {
    value: function(accessToken, done) {
      return done(null, {});
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  _loadUserProfile: {
    value: function(accessToken, done) {
      
      function loadIt() {
        return OAuth2Strategy.userProfile(accessToken, done);
      }
      function skipIt() {
        return done(null);
      }
      
      if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
        // async
        this._skipUserProfile(accessToken, function(err, skip) {
          if (err) { return done(err); }
          if (!skip) { return loadIt(); }
          return skipIt();
        });
      } else {
        let skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
        if (!skip) { return loadIt(); }
        return skipIt();
      }
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  parseErrorResponse: {
    value: (body, status) => {
      var json = JSON.parse(body);
      if (json.error) {
        tokenErrorObj.build(json.error_description, json.error, json.error_uri);
        return tokenErrorObj;
      }
      return null;
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  tokenParams: {
    value: function(options) {
      return {};
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  authorizationParams: {
    value: function(options) {
      return {};
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  loaded: {
    value: function(req, code, object) {
      let err = object.err;
      let ok = object.ok;
      let state = object.state;
      
      if (err) { return console.error(err); }
      if (!ok) { return this.fail(state, 403); }
      
      this.getOAuthAccessToken(code, (err, accessToken, refreshToken, params, results) => {
        let passReqToCallback = this._passReqToCallback;
        let verify = this._verify;
        
        // let params = this.tokenParams(options);
        // params.grant_type = 'authorization_code';
        // if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok == 'string') { // PKCE
          params.code_verifier = ok;
        }
       
        // console.log(`access token is ${accessToken}`);
        // console.log(`refresh token is ${refreshToken}`);
        // console.log(params);
          
        if (err) {
          return console.error(this._createOAuthError('Failed to obtain access token', err));
        }
        
        this._loadUserProfile(accessToken, function(err, profile) {
          if (err) {
            return console.error(err);
          }
          
          function verified(err, user, info) {
            if (err) { return console.error(err); }
            if (!user) { return this.fail(info); }
            
            info = info || {};
            if (state) { info.state = state; }
            this.success(user, info);
          }
          
          params.accessToken = accessToken;
          params.refreshToken = refreshToken;
          // params.verified = verified(err, user, info);
          
          try {
            if (passReqToCallback) {
              verify(req, params, profile);
            } else {
              verify(params, profile);
            }
          } catch (ex) {
            return console.error(ex);
          }
        });
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  authenticate: {
    value: async function(req) {
      this._stateStore.store(req);
      let code = req.query.code;
      let state = req.query.state;
      // console.log(code, state);
      
      if (req.query.error) {
        if (req.query.error == 'access_denied') {
          return console.error('MESSAGE:', req.query.error_description);
        } else {
          authError.build(req.query.error_description, req.query.error, req.query.error_uri);
          return console.error(authError);
        }
      }
      
      let callbackURL = this._callbackURL;
      
      if (callbackURL) {
        let parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(originalURL(req, { proxy: this._trustProxy }), callbackURL);
        }
      }
      
      if (req.query.code) {
        let preLoad;
        try {
          await this._stateStore.verify(req, state, function(err, ok, state) {
            preLoad = {};
            if (err) {
              preLoad.err = err;
            }
            preLoad.ok = ok;
            if (state) {
              preLoad.state = state;
            }
            console.log(preLoad);
            return preLoad;
          });
          this.loaded(req, code, preLoad);
        } catch (ex) {
          return console.error(ex);
        }
      }
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  userProfile: {
    value: function(accessToken, done) {
      return done(null, {});
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
  
  // ----- END STRATEGY AUGMENTATION -----
  
});

export default OAuth2Strategy;

