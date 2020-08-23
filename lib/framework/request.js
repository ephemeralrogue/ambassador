import http from 'http';
let req = http.IncomingMessage.prototype;

Object.defineProperties(req, {
  
  /**
   * Initiate a login session for `user`.
   *
   * Options:
   *   - `session`  Save login state in session, defaults to _true_
   *
   * Examples:
   *
   *     req.login(user, { session: false });
   *
   *     req.login(user, function(err) {
   *       if (err) { throw err; }
   *       // session saved
   *     });
   *
   * @param {User} user
   * @param {Object} options
   * @param {Function} done
   * @api public
   */
   
  login: {
    value: function(user, options, done) {
      if (typeof options == 'function') {
        done = options;
        options = {};
      }
      options = options || {};
      
      let property = 'user';
      if (this._ambassador && this._ambassador.instance) {
        property = this._ambassador.instance._userProperty || 'user';
      }
      let session = (options.session === undefined) ? true : options.session;
      
      this[property] = user;
      if (session) {
        if (!this._ambassador) { throw new Error('ambassador.initialize() middleware not in use'); }
        if (typeof done != 'function') { throw new Error('req#login requires a callback function'); }
        
        this._ambassador.instance._sm.login(this, user, function(err) {
          if (err) { self[property] = null; return done(err); }
          done();
        });
      } else {
        done && done();
      }
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /**
   * Terminate an existing login session.
   *
   * @api public
   */
   
  logout: {
    value: function() {
      var property = 'user';
      if (this._ambassador && this._ambassador.instance) {
        property = this._ambassador.instance._userProperty || 'user';
      }
      
      this[property] = null;
      if (this._ambassador) {
        this._ambassador.instance._sm.logout(this);
      }
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /**
   * Test if request is authenticated.
   *
   * @return {Boolean}
   * @api public
   */
  
  isAuthenticated: {
    value: function() {
      var property = 'user';
      if (this._ambassador && this._ambassador.instance) {
        property = this._ambassador.instance._userProperty || 'user';
      }
      
      return (this[property]) ? true : false;
    },
    writable: false,
    configurable: true,
    enumerable: true
  },
  
  /**
   * Test if request is unauthenticated.
   *
   * @return {Boolean}
   * @api public
   */
  
  isUnauthenticated: {
    value: function() {
      return !this.isAuthenticated();
    },
    writable: false,
    configurable: true,
    enumerable: true
  }
  
});

export default req;