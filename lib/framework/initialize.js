/**
 * Ambassador initialization.
 *
 * This creates a nested Ambassador object in the req object to allow for
 * the ease of passing data to other parts of the module. Intializes Ambassador
 * for incoming requests, allowing authentication strategies to be applied.
 *
 * If sessions are being utilized, applications must set up Ambassador with
 * functions to serialize a user into and out of a session.  For example, a
 * common pattern is to serialize just the user ID into the session (due to the
 * fact that it is desirable to store the minimum amount of data in a session).
 * When a subsequent request arrives for the session, the full User object can
 * be loaded from the database by ID.
 *
 * Note that additional middleware is required to persist login state, so we
 * must use the `connect.session()` middleware _before_ `ambassador.initialize()`.
 *
 * If sessions are being used, this middleware must be in use by the
 * Connect/Express application for ambassador to operate.  If the application is
 * entirely stateless (not using sessions), this middleware is not necessary,
 * but its use will not have any adverse impact.
 *
 * Examples:
 *
 *     app.use(connect.cookieParser());
 *     app.use(connect.session({ secret: 'keyboard cat' }));
 *     app.use(ambassador.initialize());
 *     app.use(ambassador.session());
 *
 *     ambassador.serializeUser(function(user, done) {
 *       done(null, user.id);
 *     });
 *
 *     ambassador.deserializeUser(function(id, done) {
 *       User.findById(id, function (err, user) {
 *         done(err, user);
 *       });
 *     });
 *
 * @return {Function}
 * @api public
 */
 
function connectInit(ambassador) {
  
  return function initialize(req, res, next) {
    req._ambassador = {};
    req._ambassador.instance = ambassador;

    if (req.session && req.session[ambassador._key]) {
      // load data from existing session
      req._ambassador.session = req.session[ambassador._key];
    }

    next();
  }
}

export default connectInit;
