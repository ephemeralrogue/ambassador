import uniqueID from '../utilities/uniqueid.js';

let sessionStore =
{
  
  build: function build(options)
  {
    if (!options.key)
    { throw new TypeError('Session-based state store requires a session key'); }
    this._key = options.key;
  },
  
  // store: function(req, callback) {
  store: function(req)
  {
    if (!req.session)
    { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Use express-session middleware?')); }
  
    let key = this._key;
    // let state = uniqueID(24);
    if (!req.session[key])
    { req.session[key] = {}; }
    req.session[key].state = req.query.state;
    // callback(null, req.query.state);
  },
  
  verify: function(req, providedState, callback)
  {
    if (!req.session)
    { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Use express-session middleware?')); }
  
    let key = this._key;
    if (!req.session[key])
    { return callback(null, false, { message: 'Unable to verify authorization request state.' }); }
  
    let state = req.session[key].state;
    if (!state)
    { return callback(null, false, { message: 'Unable to verify authorization request state.' }); }
  
    delete req.session[key].state;
    if (Object.keys(req.session[key]).length === 0)
    { delete req.session[key]; }
  
    if (state !== providedState)
    { return callback(null, false, { message: 'Invalid authorization request state.' }); }
  
    return callback(null, true);
  }
  
}

export default sessionStore;
