import OAuth2Delegate from '../embassy/oauth2delegate.js';

/* OAuth2Emissary ***

  Create the OAuth2Emissary object. Import this module alongside ambassador
  as follows:
  
    import { ambassador, discord } from 'ambassador';

  This imports this discord object and begins the chain of delegation
  through the OAuth 2.0 Embassy. The object delegation chain:

    OAuth2Emissary > OAuth2Embassy > OAuth2 > OAuth

  There are two functions necessary to successfully traverse the chain of
  authentication, authenticate, and acquire the user object from the OAuth
  2.0 provider.
  
*/

let OAuth2Ambassador = Object.create(OAuth2Delegate,
{
  
  /* populateOAuth2Ambassador ***
  
    Passing an object and verify function are required to move forward
    with authentication. The object should include your clientID and
    clientSecret, callbackURL, the authorization and token exchange URLs,
    and indicate state. Call this function when setting up ambassador, prior
    to calling the `use` function.
    
    Applications must supply a `verify` callback, for which the function
    signature is:
    
         function(err, params, results profile, done) { ... }
    
    The verify callback is responsible for finding or creating the user, and
    invoking `done` with the following arguments:
    
         done(err, user, info);
    
    `user` should be set to `false` to indicate an authentication failure.
    Additional `info` can optionally be passed as a third argument,
    typically  used to display informational messages.  If an exception
    occured, `err` should be set.
    
    Options:
    
      - `authorizationURL`  URL used to obtain an authorization grant
      - `tokenURL`          URL used to obtain an access token
      - `clientID`          identifies client to service provider
      - `clientSecret`      secret used to establish ownership of the
      client identifer
      - `callbackURL`       URL to which the service provider will redirect
      the user after obtaining authorization
      - `passReqToCallback` when `true`, `req` is the first argument to the
      verify callback (default: `false`)
    
    Examples:
    
      OAuth2Ambassador.populateOAuth2Ambassador(
      {
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: '123-456-789',
        clientSecret: 'shhh-its-a-secret'
        callbackURL: 'https://www.example.net/auth/example/callback'
      },
      function(accessToken, refreshToken, profile, done)
      {
        User.findOrCreate(..., function (err, user)
        { done(err, user); });
      });
      ambassador.use('OAuth2Ambassador');
      
    The properties passed into discordEmissary are then packed into a new
    options object that will get passed and pulled from along the delegation
    chain along with the verify callback. The verify callback that should
    include a parameter to return the user object in order to
    (de)serialize the user into a session and log them in.
    
    @param {Object} appData
    @param {Function} verify
    @api public
  */
  
  populateOAuth2Ambassador:
  {
    value: function populateOAuth2Ambassador(appData, verify)
    {
      let options =
      {
        name: 'OAuth2Ambassador',
        clientID: appData.clientID,
        clientSecret: appData.clientSecret,
        authorizeURL: appData.authorizeURL,
        accessTokenURL: appData.accessTokenURL,
        callbackURL: appData.callbackURL,
        state: appData.state,
        scope: appData.scope
      }
      
      this._populateOAuth2Delegate(options, verify);
      
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /* userProfile *
    
    This function "shadows," or does a shallow overwrite of the userProfile
    function loaded on the parent OAuth object, allowing this emissary to
    collect and parse the user object from discord. Once acquired, the user
    object is then passed to the verify function.
    
  */
  
  userProfile:
  {
    value: function userProfile(results, done)
    {
      // userProfile function override
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
  
});

export default OAuth2Ambassador;