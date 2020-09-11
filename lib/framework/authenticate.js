import http from 'http';
import connect  from './connect.js';
import IncomingMessageExt from './request.js';
import authenticationError from '../errors/authenticationerror.js';

const authenticateError = Object.create(authenticationError);

/* authenticate ***
  
  Authenticates requests.
  
  Applies the `name`ed strategy (or ambassadors) to the incoming request, in
  order to authenticate the request.  If authentication is successful, the
  user will be logged in and populated at `req.user` and a session will be
  established by default.  If authentication fails, an unauthorized response
  will be sent.
  
  Options:
    - `session`           Save login state in session, defaults to _true_
    - `successRedirect`   After successful login, redirect to given URL
    - `successMessage`    True to store success message in
                          req.session.messages, or a string to use as
                          override message for success.
    - `successFlash`      True to flash success messages or a string to use
                          as a flash message for success (overrides any from
                          the strategy itself).
    - `failureRedirect`   After failed login, redirect to given URL
    - `failureMessage`    True to store failure message in
                          req.session.messages, or a string to use as
                          override message for failure.
    - `failureFlash`      True to flash failure messages or a string to use
                          as a flash message for failures (overrides any
                          from the strategy itself).
    - `assignProperty`    Assign the object provided by the verify callback
                          to given property
  
  An optional `callback` can be supplied to allow the application to
  override the default manner in which authentication attempts are handled. 
  The callback has the following signature, where `user` will be set to the
  authenticated user on a successful authentication attempt, or `false`
  otherwise.  An optional `info` argument will be passed, containing
  additiona details provided by the strategy's verify callback - this could
  be information about a successful authentication or a challenge message
  for a failed authentication. An optional `status` argument will be passed
  when authentication fails - this could be a HTTP response code for a
  remote authentication failure or similar.
  
    app.get('/protected', function(req, res, next) {
        ambassador.authenticate('local', function(err, user, info, status) {
          if (err) { return next(err) }
          if (!user) { return res.redirect('/signin') }
          res.redirect('/account');
        })(req, res, next);
      });
  
  Note that if a callback is supplied, it becomes the application's
  responsibility to log-in the user, establish a session, and otherwise
  perform the desired operations.
  
  Examples:
  
      ambassador.authenticate('local',
      { successRedirect: '/', failureRedirect: '/login' });
      
      ambassador.authenticate('basic', { session: false });
      
      ambassador.authenticate('twitter');
  
  @param {Strategy|String|Array} name
  @param {Object} options
  @param {Function} callback
  @return {Function}
  @api public
  
*/
 
function connectAuth(ambassador, input)
{
  let { name, options, callback } = input
  options = options || {};
  
  let multi = true;
  if (!Array.isArray(name))
  {
    name = [ name ];
    multi = false;
  }
  
  return function authenticate(req, res, next)
  {
    if (http.IncomingMessage.prototype.login
        && http.IncomingMessage.prototype.login !== IncomingMessageExt.login)
    { connect.__monkeypatchNode(); }
    
    let failures = [];
    
    function allFailed()
    {
      /*
      if (callback)
      {
        if (!multi)
        {
          return callback(null, false, failures[0].challenge, failures[0].status);
        } else {
          var challenges = failures.map(function(f) { return f.challenge; });
          var statuses = failures.map(function(f) { return f.status; });
          return callback(null, false, challenges, statuses);
        }
      }
      */
      
      // Ambassadors are ordered by priority.  For the purpose of flashing a
      // message, the first failure will be displayed.
      let failure = failures[0] || {};
      let challenge = failure.challenge || {};
      let msg;
    
      if (options.failureFlash)
      {
        let flash = options.failureFlash;
        if (typeof flash == 'string')
        { flash = { type: 'error', message: flash }; }
        flash.type = flash.type || 'error';
      
        let type = flash.type || challenge.type || 'error';
        msg = flash.message || challenge.message || challenge;
        if (typeof msg == 'string')
        { req.flash(type, msg);}
      }
      
      if (options.failureMessage)
      {
        msg = options.failureMessage;
        if (typeof msg == 'boolean')
        { msg = challenge.message || challenge; }
        if (typeof msg == 'string')
        {
          req.session.messages = req.session.messages || [];
          req.session.messages.push(msg);
        }
      }
      
      if (options.failureRedirect)
      { return res.redirect(options.failureRedirect); }
    
      // When failure handling is not delegated to the application, the default
      // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
      // header will be set according to the ambassadors in use (see
      // actions#fail).  If multiple ambassadors failed, each of their challenges
      // will be included in the response.
      
      let rchallenge = [];
      let status = failure.status;
      let rstatus;
      
      failures.map((j) =>
      {
        failure = j;
        challenge = failure.challenge;
        status = failure.status;
        
        rstatus = rstatus || status;
        if (typeof challenge == 'string')
        { rchallenge.push(challenge); }
      });
      
      res.statusCode = rstatus || 401;
      if (res.statusCode == 401 && rchallenge)
      { res.setHeader('WWW-Authenticate', rchallenge); }
      if (options.failWithError)
      { return next(authenticateError.build(http.STATUS_CODES[res.statusCode], rstatus)); }
      res.end(http.STATUS_CODES[res.statusCode]);
    } // end function allFailed
    
    (function attempt(i)
    {
      let layer = name[i];
      
      // If no more ambassadors exist in the chain, authentication has failed.
      if (!layer)
      { return allFailed(); }
    
      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      
      let emissary, prototype;
      if (typeof layer.authenticate == 'function')
      {
        emissary = layer;
      } else {
        prototype = ambassador._loadEmissary(layer);
        if (!prototype) { return next(new Error(`Unknown authentication strategy "${layer}"`)); }
        emissary = Object.create(prototype);
      }
        
      Object.defineProperties(emissary,
      {
        /* BEGIN EMISSARY AUGMENTATION ************************************
        Augment the new strategy instance with action functions. These
        action functions are bound via closure the the request/response
        pair. The end goal of the strategy is to invoke *one* of these
        action methods, in order to indicate successful or failed
        authentication, redirect to a third-party identity provider, etc.
        *******************************************************************/
        
        /* error ***
          
          Internal error while performing authentication.
          
          Ambassadors should call this function when an internal error occurs
          during the process of performing authentication; for example, if
          the user directory is not available.
          
          @param {Error} err
          @api public
          
        */
        
        error:
        {
          value: function error(err)
          { return Promise.reject(err); },
          writable: false,
          configurable: true,
          enumerable: true
        },
        
        /* fail ***
          
          Fail authentication, with optional `challenge` and `status`,
          defaulting to 401. Ambassadors should call this function to fail
          an authentication attempt.
          
          @param {String} challenge
          @param {Number} status
          @api public
          
        */
         
        fail:
        {
          value: function fail(challenge, status)
          {
            if (typeof challenge == 'number')
            {
              status = challenge;
              challenge = undefined;
            }
            // push this failure into the accumulator and attempt
            // authentication using the next strategy
            failures.push({ challenge: challenge, status: status });
            attempt(i + 1);
          },
          writable: false,
          configurable: true,
          enumerable: true
        },
        
        /* pass ***
          
          Pass without making a success or fail decision.
          
          Under most circumstances, ambassadors should not need to call this
          function.  It exists primarily to allow previous authentication
          state to be restored, for example from an HTTP session.
          
          @api public
          
        */
        
        pass:
        {
          value: function pass()
          { next(); },
          writable: false,
          configurable: true,
          enumerable: true
        },
        
        /* redirect ***
           
          Redirect to `url` with optional `status`, defaulting to 302.
          Ambassadors should call this function to redirect the user (via
          their user agent) to a third-party website for authentication.
          
          @param {String} url
          @param {Number} status
          @api public
          
        */
        
        redirect:
        {
          value: function redirect(url, status)
          {
            // NOTE:
            // Do not use `res.redirect` from Express, because it can't
            // decide what it wants.
            //
            // Express 2.x: res.redirect(url, status)
            // Express 3.x: res.redirect(status, url) -OR-
            //              res.redirect(url, status)
            //              - as of 3.14.0, deprecated warnings are issued
            //              if res.redirect(url, status) is used
            // Express 4.x: res.redirect(status, url)
            //              - all versions (as of 4.8.7) continue to accept
            //              res.redirect(url, status) but issue deprecated
            //              versions
            
            res.statusCode = status || 302;
            res.setHeader('Location', url);
            res.setHeader('Content-Length', '0');
            res.end();
          },
          writable: false,
          configurable: true,
          enumerable: true
        },
        
        /* success ***
          
          Authenticate `user`, with optional `info`. Ambassadors should call
          this function to successfully authenticate a user. `user` should
          be an object supplied by the application after it has been given
          an opportunity to verify credentials. `info` is an optional
          argument containing additional user information. This is useful
          for third-party authentication ambassadors to pass profile details.
          
          @param {Object} user
          @param {Object} info
          @api public
          
        */
        
        success:
        {
          value: function success(user, info)
          {
            if (callback)
            { return callback(null, user, info); }
            
            info = info || {};
            let msg;
            
            if (options.successFlash)
            {
              let flash = options.successFlash;
              if (typeof flash == 'string')
              { flash = { type: 'success', message: flash }; }
              flash.type = flash.type || 'success';
            
              let type = flash.type || info.type || 'success';
              msg = flash.message || info.message || info;
              if (typeof msg == 'string')
              { req.flash(type, msg); }
            }
            
            if (options.successMessage)
            {
              msg = options.successMessage;
              if (typeof msg == 'boolean')
              { msg = info.message || info; }
              if (typeof msg == 'string')
              {
                req.session.messages = req.session.messages || [];
                req.session.messages.push(msg);
              }
            }
            
            if (options.assignProperty)
            {
              req[options.assignProperty] = user;
              return next();
            }
          
            req.login(user, options, function(err)
            {
              if (err)
              { return next(err); }
              
              function complete()
              {
                if (options.successReturnToOrRedirect)
                {
                  let url = options.successReturnToOrRedirect;
                  if (req.session && req.session.returnTo)
                  {
                    url = req.session.returnTo;
                    delete req.session.returnTo;
                  }
                  return res.redirect(url);
                }
                if (options.successRedirect)
                { return res.redirect(options.successRedirect); }
                next();
              }
              
              if (options.authInfo !== false)
              {
                ambassador.transformAuthInfo(info, req, function(err, tinfo)
                {
                  if (err)
                  { return next(err); }
                  req.authInfo = tinfo;
                  complete();
                });
              } else {
                complete();
              }
            });
          },
          writable: false,
          configurable: true,
          enumerable: true
        }
        
        /***************** END EMBASSY AUGMENTATION ***********************/
      });
      
      // console.log(prototype);
      emissary._authenticate(req);
      
    })(0); // end IIFE "attempt"
  }
}

export default connectAuth;
