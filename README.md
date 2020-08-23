# ambassador

ambassador is [Express](http://expressjs.com/)-compatible authentication
middleware for [Node.js](http://nodejs.org/), featuring JS Object Delegation
and full support for ES6 modules.

ambassador manages authentication. The primary concept is that ambassador assists in
utilizing third-party services to log users in and out of the designated application.
ambassador does not mount routes or assume any particular database schema, allowing
a great deal of flexibility in terms of implementation. As the developer, you determine
how to manage user and session data; ambassador simply negotiates the exchange of 
authentication codes for access tokens via emissary, and provides the means to
retrieve user data from the OAuth source. Currently, ambassador handles authentication
via the OAuth2 protocol. More services will be added in the future.

## Install

```
$ npm install @nonsensecodes/ambassador
```

## Usage

#### Strategies

Before authenticating requests, the strategy (or strategies) used by an
application must be configured. This is done by passing OAuth2 credentials
to the OAuth2 strategy. The strategy can then be called to handle authentication:

```javascript
import { ambassador, OAuth2Strategy } from '@nonsensecodes/ambassador';

OAuth2Strategy.build({
  clientID: client_id,
  clientSecret: client_secret,
  authorizeURL: url,
  accessTokenURL: url,
  callbackURL: callback
});

ambassador.use(OAuth2Strategy, function verify());
```

#### Sessions

ambassador will maintain persistent login sessions.  In order for persistent
sessions to work, the authenticated user must be serialized to the session, and
deserialized when subsequent requests are made.

ambassador does not impose any restrictions on how your user records are stored.
Instead, you provide functions to ambassador which implements the necessary
serialization and deserialization logic.  In a typical application, this will be
as simple as serializing the user ID, and finding the user by ID when
deserializing.

```javascript
ambassador.serializeUser(function(user, done) {
  done(null, user.id);
});

ambassador.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
```

#### Middleware

To use ambassador in an [Express](http://expressjs.com/) or
[Connect](http://senchalabs.github.com/connect/)-based application, configure it
with the required `ambassador.initialize()` middleware.  If your application uses
persistent login sessions (recommended, but not required), `ambassador.session()`
middleware must also be used.

```javascript
var app = express();
app.use(require('serve-static')(__dirname + '/../../public'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));
app.use(ambassador.initialize());
app.use(ambassador.session());
```

#### Authenticate Requests

ambassador provides an `authenticate()` function, which is used as route
middleware to authenticate requests.

```javascript
app.post('/login', 
  ambassador.authenticate('oauth2', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });
```

## License

  ambassador: your OAuth2 authentication negotiator
  Copyright (C) 2020  Joshua Alexander Castaneda

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

  This software is based on:
  [Passport](https://github.com/jaredhanson/passport)
  [The MIT License](http://opensource.org/licenses/MIT)

  Copyright (c) 2011-2019 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
