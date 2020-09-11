import OAuth2Delegate from '../embassy/oauth2delegate.js';

/* discordEmissary ***

  Create the discord object that contains the prepopulated authorize and
  token links, name, and identify and email scope. Import this module
  alongside ambassador as follows:
  
      import { ambassador, discordEmissary } from 'ambassador';
  
  This imports this discord object and begins the chain of delegation
  through to the OAuth Embassy. The object delegation chain:
  
      emissary > OAuth2Delegate > OAuth2Ambassador > OAuthEmbassy
  
  There are two functions necessary to successfully traverse the chain of
  authentication, authenticate, and acquire the user object from Discord.
  
*/

let discordEmissary = Object.create(OAuth2Delegate,

/* BEGIN EMISSARY AUGMENTATION *******************************************
Augment the Ambassador object with functions that will populate the
credentials for the OAuth provider, as well as override any provided
functions in order to pass along additional paramters that may not already
be included in a base OAuth request.
**************************************************************************/

{
  
  /* populateDiscordEmissary ***
  
    Passing an object and verify function are required to move forward
    with authentication. The object should include your clientID and
    clientSecret, callbackURL, and indicate state. Call this function when
    setting up ambassador, prior to calling the `use` function.
    
    Applications must supply a `verify` callback, for which the function
    signature is:
    
         function(err, params, results, profile, done) { ... }
    
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
    
        discordEmissary.populateDiscordEmissary(
        {
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: '123-456-789',
          clientSecret: 'shhh-its-a-secret'
          callbackURL: 'https://www.example.net/auth/example/callback'
        }, function(accessToken, refreshToken, profile, done)
        {
          User.findOrCreate(..., function (err, user)
          { done(err, user); });
        });
        ambassador.use('discordEmissary');
      
    The properties passed into discordEmissary are then packed into a new
    options object that will get passed and pulled from along the delegation
    chain along with the verify callback. The verify callback that should
    include a parameter to return the user object in order to
    (de)serialize the user into a session and log them in.
    
    @param {Object} appData
    @param {Function} verify
    @api public
    
  */
  
  populateDiscordEmissary:
  {
    value: function populatediscordEmissary(appData, verify)
    {
      let options =
      {
        name: 'discord',
        clientID: appData.clientID,
        clientSecret: appData.clientSecret,
        authorizeURL: 'https://discord.com/api/oauth2/authorize',
        accessTokenURL: 'https://discord.com/api/oauth2/token',
        callbackURL: appData.callbackURL,
        state: appData.state,
        scope: 'identify email'
      }
      this._populateOAuth2Delegate(options, verify);
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /*
  serialize: {
    value: {
      fn:,
      
      req:,
      
      done:,
      
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  */
  
  /* userProfile ***
  
    This function "shadows," or does a shallow overwrite of the userProfile
    function declared on the parent OAuth object, OAuthEmbassy. This
    function is captured by the `_loaded` function in OAuth2Delegate and
    passed to `_loadUserProfile`. Upon being called, `userProfile` collects
    and parses the user object from discord. Once acquired, the user object
    is then passed to the verify function at the end of the
    `_loadUserProfile` callback.
    
  */
  
  userProfile:
  {
    value: function userProfile(results)
    {
      return new Promise(function promiseUserProfile(resolve, reject)
      {
        discordEmissary.acquireUserProfile('https://discord.com/api/v8/users/@me', results)
        .then(profile => resolve.call(discordEmissary, profile))
        .catch(err =>
        {
          console.log('Error acquiring user profile from Ambassador');
          return console.error(err);
        });
      });
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
/* END EMISSARY AUGMENTATION ********************************************/

});

export default discordEmissary;