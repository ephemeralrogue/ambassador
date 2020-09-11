import uniqueID from '../utilities/uniqueid.js';

let PKCESessionStore = {};

Object.defineProperties(PKCESessionStore,
{

  /* build ***
  
    Creates an instance of `SessionStore`. This is the state store
    implementation for the OAuth2Strategy used when the `state` option is
    enabled.  It generates a random state and stores it in `req.session` and
    verifies it when the service provider redirects the user back to the
    application. This state store requires session support.  If no session
    exists, an error will be thrown.
  
    Options:
  
      - `key`  The key in the session under which to store the state
  
    @constructor
    @param {Object} options
    @api public
    
  */
 
  build:
  {
    value: function build(options)
    {
      if (!options.key)
      { throw new TypeError('Session-based state store requires a session key'); }
      this._key = options.key;
    },
    writable: false,
    configurable: true,
    enumberable: true
  },

  /* _PKCEstore ***
    
    Store request state. This implementation simply generates a random
    string and stores the value in the session, where it will be used for
    verification when the user is redirected back to the application.

    @param {Object} req
    @param {Function} callback
    @api protected
    
  */
  
  _store:
  {
    value: function store(req)
    {
      let key = this._key;
      let state = {
        handle: uniqueID(24),
        code_verifier: verifier
      }
      
      if (!req.session)
      { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }
      
      if (!req.session[key])
      { req.session[key] = {}; }
      
      req.session[key].state = state;
      callback(null, state.handle);
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _PKCEverify ***

    Verify request state. This implementation simply compares the state
    parameter in the request to the value generated earlier and stored in
    the session.
  
    @param {Object} req
    @param {String} providedState
    @param {Function} callback
    @api protected
    
  */
  
  _verifyState:
  {
    value: function verifyState(req, providedState)
    {
      let key = this._key;
      let state = req.session[key].state;
      
      if (!req.session) { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }
    
      if (!req.session[key]) {
        return callback(null, false, { message: 'Unable to verify authorization request state.' });
      }
      
      if (!state) {
        return callback(null, false, { message: 'Unable to verify authorization request state.' });
      }
    
      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }
    
      if (state.handle !== providedState) {
        return callback(null, false, { message: 'Invalid authorization request state.' });
      }
    
      return callback(null, state.code_verifier);
    },
    writable: false,
    configurable: true,
    enumerable: false
  }
});

export default PKCESessionStore;
