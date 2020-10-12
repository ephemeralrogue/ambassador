// Load modules.
import url from 'url';
import { merge, originalURL } from '../utilities/utils.js';
import OAuth1Ambassador from './oauth1ambassador.js';

/****
Creates an instance of `OAuthStrategy`.

The OAuth authentication strategy authenticates requests using the OAuth
protocol.

OAuth provides a facility for delegated authentication, whereby users can
authenticate using a third-party service such as Twitter.  Delegating in
this manner involves a sequence of events, including redirecting the user
to the third-party service for authorization.  Once authorization has been
obtained, the user is redirected back to the application and a token can be
used to obtain credentials.

Applications must supply a `verify` callback, for which the function
signature is:

    function(token, tokenSecret, profile, cb) { ... }

The verify callback is responsible for finding or creating the user, and
invoking `cb` with the following arguments:

    done(err, user, info);

`user` should be set to `false` to indicate an authentication failure.
Additional `info` can optionally be passed as a third argument, typically
used to display informational messages.  If an exception occured, `err`
should be set.

Options:

  - `requestTokenURL`       URL used to obtain an unauthorized request token
  - `accessTokenURL`        URL used to exchange a user-authorized request
  token for an access token
  - `userAuthorizationURL`  URL used to obtain user authorization
  - `consumerKey`           identifies client to service provider
  - `consumerSecret`        secret used to establish ownership of the
  consumer key
  - 'signatureMethod'       signature method used to sign the request
  (default: 'HMAC-SHA1')
  - `callbackURL`           URL to which the service provider will redirect
  the user after obtaining authorization
  - `passReqToCallback`     when `true`, `req` is the first argument to the
  verify callback (default: `false`)

Examples:

    passport.use(new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: '123-456-789',
        consumerSecret: 'shhh-its-a-secret'
        callbackURL: 'https://www.example.net/auth/example/callback'
      },
      function(token, tokenSecret, profile, cb) {
        User.findOrCreate(..., function (err, user) {
          cb(err, user);
        });
      }
    ));

@constructor
@param {Object} options
@param {Function} verify
@api public
*****/
 
const OAuth1Delegate = Object.create(OAuth1Ambassador,
{
  /******************* BEGIN DELEGATE AUGMENTATION ***********************
  Augment the new strategy instance with action functions. These functions
  serve to facilitate the exchange of an authorization code for an access
  token. The goal of these functions is to negotiate the exchange, capture
  the user's profile data, and pass it on to the appropriate callback in
  order to successfully log the user into the site.
  ************************************************************************/
  
  /* _populateOAuth1Delegate ***
    
    This takes the given options object and populates the strategy with the
    necessary information to facilitate a successfully authorization code
    and access token exchange. The following options are required to build
    the OAuth object and populate this embassy with the proper credentials:
      requestTokenURL
      accessTokenURL
      consumerKey
      consumerSecret
      '1.0'
      null
      signatureMethod || 'HMAC-SHA1'
      null
      customHeaders
       
  */
  
  _populateOAuth1Delegate:
  {
    value: function populateOAuth1Delegate(options, verify)
    {
      if (typeof options == 'function')
      {
        verify = options;
        options = undefined;
      }
      options = options || {};
      
      if (!verify)
      { throw new TypeError('OAuthStrategy requires a verify callback'); }
      if (!options.requestTokenURL)
      { throw new TypeError('OAuthStrategy requires a requestTokenURL option'); }
      if (!options.accessTokenURL)
      { throw new TypeError('OAuthStrategy requires a accessTokenURL option'); }
      if (!options.userAuthorizationURL)
      { throw new TypeError('OAuthStrategy requires a userAuthorizationURL option'); }
      if (!options.consumerKey)
      { throw new TypeError('OAuthStrategy requires a consumerKey option'); }
      if (options.consumerSecret === undefined)
      { throw new TypeError('OAuthStrategy requires a consumerSecret option'); }
      
      this.name = options.name || 'oauth';
      
      this._populateOAuth1Ambassador(options, verify);
      this._userAuthorizationURL = options.userAuthorizationURL;
      this._key = options.sessionKey || 'oauth';
      this._requestTokenStore = options.requestTokenStore || new SessionRequestTokenStore({ key: this._key });
     
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /**
   * Authenticate request by delegating to a service provider using OAuth.
   *
   * @param {Object} req
   * @api protected
   */
  
  authenticate:
  {
    value: function authenticate(req, options)
    {
      options = options || {};
      
      let meta =
      {
        requestTokenURL: this._oauth._requestUrl,
        accessTokenURL: this._oauth._accessUrl,
        userAuthorizationURL: this._userAuthorizationURL,
        consumerKey: this._oauth._consumerKey
      }
      
      if (req.query && req.query.oauth_token)
      {
        /****
        The request being authenticated contains an oauth_token parameter
        in the query portion of the URL.  This indicates that the service
        provider has redirected the user back to the application, after
        authenticating the user and obtaining their authorization.
        
        The value of the oauth_token parameter is the request token.
        Together with knowledge of the token secret (stored in the session),
        the request token can be exchanged for an access token and token
        secret.
        
        This access token and token secret, along with the optional ability
        to fetch profile information from the service provider, is
        sufficient to establish the identity of the user.
        ****/
        
        let oauthToken = req.query.oauth_token;
        
        try
        {
          var arity = this._requestTokenStore.get.length;
          if (arity == 4)
          {
            this._requestTokenStore.get(req, oauthToken, meta, loaded);
          } else { // arity == 3
            this._requestTokenStore.get(req, oauthToken, this.loaded);
          }
        } catch (ex) {
          return this.error(ex);
        }
      } else {
        
        /****
        In order to authenticate via OAuth, the application must obtain a
        request token from the service provider and redirect the user to
        the service provider to obtain their authorization.  After
        authorization has been approved the user will be redirected back the
        application, at which point the application can exchange the request
        token for an access token.
        
        In order to successfully exchange the request token, its
        corresponding token secret needs to be known.  The token secret will
        be temporarily stored in the session, so that it can be retrieved
        upon the user being redirected back to the application.
        *****/
        
        let params = this.tokenParams(options);
        let callbackURL = options.callbackURL || this._callbackURL;
        if (callbackURL) {
          let parsed = url.parse(callbackURL);
          if (!parsed.protocol)
          {
            // The callback URL is relative, resolve a fully qualified URL
            // from the URL of the originating request.
            callbackURL = url.resolve(originalURL(req, { proxy: this._trustProxy }), callbackURL);
          }
        }
        params.oauth_callback = callbackURL;
        
        this._oauth.getOAuthRequestToken(params, function(err, token, tokenSecret, params)
        {
          if (err)
          { return this.error(this._createOAuthError('Failed to obtain request token', err)); }
          
          // NOTE: params will contain an oauth_callback_confirmed property
          // set to true, if the server supports OAuth 1.0a.
          // { oauth_callback_confirmed: 'true' }
    
          function stored(err)
          {
            if (err)
            { return this.error(err); }
    
            this.parsed = url.parse(this._userAuthorizationURL, true);
            parsed.query.oauth_token = token;
            if (!params.oauth_callback_confirmed && callbackURL)
            {
              // NOTE: If oauth_callback_confirmed=true is not present when
              // issuing a request token, the server does not support OAuth
              // 1.0a.  In this circumstance, `oauth_callback` is passed
              // when redirecting the user to the service provider.
              parsed.query.oauth_callback = callbackURL;
            }
            merge(parsed.query, this.userAuthorizationParams(options));
            delete parsed.search;
            let location = url.format(parsed);
            this.redirect(location);
          }
          
          try
          {
            var arity = this._requestTokenStore.set.length;
            if (arity == 5)
            {
              this._requestTokenStore.set(req, token, tokenSecret, meta, stored);
            } else { // arity == 4
              this._requestTokenStore.set(req, token, tokenSecret, stored);
            }
          } catch (ex) {
            return this.error(ex);
          }
        });
      }
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  loaded:
  {
    value: function loaded(err, oauthTokenSecret, state)
    {
      if (err)
      { return this.error(err); }
      if (!oauthTokenSecret)
      { return this.fail(state, 403); }
    
      // NOTE: The oauth_verifier parameter will be supplied in the query portion
      //       of the redirect URL, if the server supports OAuth 1.0a.
      let oauthVerifier = req.query.oauth_verifier || null;
    
      this.getOAuthAccessToken(oauthToken, oauthTokenSecret, oauthVerifier, function(err, token, tokenSecret, params)
      {
        if (err)
        { return this.error(this._createOAuthError('Failed to obtain access token', err)); }
      
        function destroyed(err)
        {
          if (err)
          { return this.error(err); }
          
          let passThru =
          {
            protocol: 'oauth',
            userProfile: this.userProfile,
            skipUserProfile: this._skipUserProfile,
            token: token,
            tokenSecret: tokenSecret,
            params: params,
            accessToken: undefined
          }
      
          this._loadUserProfile(passThru, function(err, profile)
          {
            if (err)
            { return this.error(err); }
        
            function verified(err, user, info)
            {
              if (err)
              { return this.error(err); }
              if (!user)
              { return this.fail(info); }
              
              info = info || {};
              if (state)
              { info.state = state; }
              this.success(user, info);
            }
        
            try
            {
              if (this._passReqToCallback)
              {
                var arity = this._verify.length;
                if (arity == 6)
                {
                  this._verify(req, token, tokenSecret, params, profile, verified);
                } else { // arity == 5
                  this._verify(req, token, tokenSecret, profile, verified);
                }
              } else {
                var arity = this._verify.length;
                if (arity == 5)
                {
                  this._verify(token, tokenSecret, params, profile, verified);
                } else { // arity == 4
                  this._verify(token, tokenSecret, profile, verified);
                }
              }
            } catch (ex) {
              return this.error(ex);
            }
          });
        }
      
        // The request token has been exchanged for an access token. Since
        // the request token is a single-use token, that data can be removed
        // from the store.
        
        try
        {
          var arity = this._requestTokenStore.destroy.length;
          if (arity == 4)
          {
            this._requestTokenStore.destroy(req, oauthToken, meta, destroyed);
          } else { // arity == 3
            this._requestTokenStore.destroy(req, oauthToken, destroyed);
          }
        } catch (ex) {
          return this.error(ex);
        }
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
}

export default OAuth1Delegate;
