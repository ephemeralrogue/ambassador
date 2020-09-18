import pause from 'pause';

const sessionAmbassador = {};

Object.defineProperties(sessionAmbassador,

/* BEGIN SESSION AMBASSADOR AUGMENTATION **********************************
Augment the OAuth object with action functions. These provide properties
and functions that are common to both OAuth 1.0 and 2.0 authentication
protocols, and assist in the exchange of an authorization code for an
access token. The goal of these functions is to negotiate the exchange,
capture the user's profile data, and pass it on to the appropriate callback
in order to successfully log the user into the site.
***************************************************************************/

{
  
  _populateSessionAmbassador:
  {
    value: function populateSessionAmbassador(options, deserializeUser)
    {
      if (typeof options == 'function')
      {
        deserializeUser = options;
        options = undefined;
      }
      options = options || {};
      
      this.name = 'session';
      this._deserializeUser = deserializeUser;
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /* _authenticate ***
    
    Authenticate request based on the current session state.
    
    The session authentication strategy uses the session to restore any
    login state across requests. If a login session has been established,
    `req.user` will be populated with the current user. This is registered
    automatically by ambassador. As such, it is a protected function and
    should not be called directly.
    
    @param {Object} req
    @param {Object} options
    @api protected
    
  */
  
  _authenticate:
  {
    value: function authenticate(req, options)
    {
      if (!req._ambassador)
      { return this.error(new Error('ambassador.initialize() middleware not in use')); }
      options = options || {};
      
      let su;
      if (req?._ambassador?.session)
      { su = req._ambassador.session.user; }
    
      if (su || su === 0)
      {
        // NOTE: Stream pausing is desirable in the case where later
        //       middleware is listening for events emitted from request.
        //       For discussion on the matter, refer to:
        //       https://github.com/jaredhanson/ambassador/pull/106
        
        let paused = options.pauseStream ? pause(req) : null;
        this._deserializeUser(su, req, function deserializeCB(err, user)
        {
          if (err)
          { return this.error(err); }
          
          if (!user)
          {
            delete req._ambassador.session.user;
          } else {
            // TODO: Remove instance access
            let property = req._ambassador.instance._userProperty || 'user';
            req[property] = user;
          }
          
          this.pass();
          if (paused)
          { paused.resume(); }
        });
      } else {
        this.pass();
      }
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
  
});

export default sessionAmbassador;
