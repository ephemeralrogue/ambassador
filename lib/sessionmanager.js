const sessionManager = {}

Object.defineProperties(sessionManager,

/* BEGIN SESSION MANAGER AUGMENTATION *************************************
Augment the OAuth object with action functions. These provide properties
and functions that are common to both OAuth 1.0 and 2.0 authentication
protocols, and assist in the exchange of an authorization code for an
access token. The goal of these functions is to negotiate the exchange,
capture the user's profile data, and pass it on to the appropriate callback
in order to successfully log the user into the site.
***************************************************************************/

{
  _populateSessionManager:
  {
    value: function populateSessionManager(options, serializeUser)
    {
      if (typeof options == 'function')
      {
        serializeUser = options;
        options = undefined;
      }
      options = options || {};
      
      this._key = options.key || 'ambassador';
      this._serializeUser = serializeUser;
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  // Where the fuck does this get called?!
  login:
  {
    value: function login(req, user, cb)
    {
      this._serializeUser(user, req, function serializeCB(err, obj)
      {
        if (err)
        { return cb(err); }
        
        if (!req._ambassador.session)
        { req._ambassador.session = {}; }
        
        req._ambassador.session.user = user;
        
        if (!req.session)
        { req.session = {}; }
        
        req.session[this._key] = req._ambassador.session;
        cb();
      });
    },
    writable: true,
    configurable: true,
    enumerable: true
  },
  
  logout:
  {
    value: function logout(req, cb)
    {
      if (req?._ambassador?.session)
      { delete req._ambassador.session.user; }
      cb && cb();
    },
    writable: true,
    configurable: true,
    enumerable: true
  }
  
});

export default sessionManager;
