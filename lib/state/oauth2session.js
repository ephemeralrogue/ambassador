import uniqueID from '../utilities/uniqueid.js';

let OAuth2SessionStore = {};

Object.defineProperties(OAuth2SessionStore,
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
    enumerable: true
  },
  
  /* _store
    
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
      console.log('key:', key);
      let state = uniqueID(24);
      console.log('state:', state);
      
      /*
      this._state =
      {
        state: state,
        sessionID: req.session.id
      }
      */
      
      return new Promise((resolve, reject) =>
      {
        if (!req.session)
        { reject(new Error('OAuth 2.0 authentication requires session support when using state. Use express-session middleware?')); }
        
        if (!req.session[key])
        { req.session[key] = {}; }
        req.session[key].state = state;
        // req.session.save();
        resolve(req);
      });
    },
    writable: false,
    configurable: true,
    enumerable: false
  },
  
  /* _verifyState ***
    
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
    value: function verifyState(req)
    {
      let key = this._key;
      // console.log('this._state:');
      // console.log(this._state);
      let state = req.session[key].state;
      // let state = this._state.state;
      let returnedState = req.query.state;
      let stateReference =
      {
        ok: false,
        state: state
      };
      
      return new Promise((resolve, reject) =>
      {
        switch (true)
        {
          case !req.session:
            stateReference.err = new Error('OAuth 2.0 authentication requires session support when using state. Use express-session middleware?');
            return reject(verifyState);
          case !req.session[key]:
            stateReference.err = { message: 'Unable to verify authorization request state.' };
            return reject(verifyState);
          case !state:
            stateReference.err = { message: 'Unable to verify authorization request state.' };
            return reject(verifyState);
          case state !== returnedState:
            stateReference.err = { message: 'Invalid authorization request state.' };
            return reject(verifyState);
          default:
            stateReference.err = null;
            stateReference.ok = true;
            stateReference.state = req.session[key].state
            
            /*
            delete req.session[key].state;
            if (Object.keys(req.session[key]).length === 0)
            { delete req.session[key]; }
            */
            
            console.log(stateReference);
            return resolve(stateReference);
        }
      });
    },
    writable: false,
    configurable: true,
    enumerable: false
  }
});

export default OAuth2SessionStore;
