let sessionManager = {}

Object.defineProperties(sessionManager,
{
  buildSM:
  {
    value: function buildSM(options, serializeUser)
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
        
        req._ambassador.session.user = obj;
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
      if (req._ambassador && req._ambassador.session)
      { delete req._ambassador.session.user; }
      cb && cb();
    },
    writable: true,
    configurable: true,
    enumerable: true
  }
  
});

export default sessionManager;
