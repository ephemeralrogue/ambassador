import http from 'http';
import IncomingMessageExt from './request.js';
  
/**
 * Resolve login/logout functions on req object.
 *
 * This function augments the req object with login/logout functions. This function
 * is called in ./authenticate.js as part of a check to see if these functions already
 * exist on the req object, and if the functions there match the functions written in
 * ./request.js.
 *
 * @api protected
 */
 
 let connect = {};
 
 Object.defineProperties(connect, {
   __monkeypatchNode: {
     value: function() {
      http.IncomingMessage.prototype.login = IncomingMessageExt.login;
      http.IncomingMessage.prototype.logout = IncomingMessageExt.logout;
      http.IncomingMessage.prototype.isAuthenticated = IncomingMessageExt.isAuthenticated;
      http.IncomingMessage.prototype.isUnauthenticated = IncomingMessageExt.isUnauthenticated;
    },
    writable: false,
    configurable: true,
    enumerable: false
  }
});

export default connect;