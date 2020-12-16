# ambassador  

ambassador is a Promise-based, [Express](http://expressjs.com/)-compatible
authentication middleware for [Node.js](http://nodejs.org/), featuring JS
Object Delegation a ES6 modules.  

ambassador manages authentication. The primary concept is that ambassador
assists in utilizing third-party services to log users in and out of the
designated application. ambassador is database-agnostic, allowing for a
great deal of flexibility in terms of implementation. As the developer, you
determine how to manage user and session data; ambassador simply negotiates
the exchange of authentication codes for access tokens via OAuth 1.0/2.0
emissaries, and provides the means to retrieve user data from the OAuth
source. Currently, ambassador handles authentication via the OAuth2
protocol, with emissaries to handle authentication through Discord and
generic OAuth 2.0. More emissaries will be added in the future.  

## Install  

```
$ npm install @nonsensecodes/ambassador
```

## Usage  

#### Emissaries  

Before authenticating requests, the Emissary (or Emissaries) used by your
application must be configured. This is done by passing your app's OAuth
credentials to each Emissary you're using. Every Emissary has a 'populate'
method that uses your credentials to build and populate the authentication
object for that particular Emissary. First, import ambassador and the
Emissaries you plan to use. Next, call each Emissary's populate method with
an object containing your credentials as the first parameter, and a verify
function as your second parameter. Finally, call ambassador with the given
Emissary as a single parameter. You'll call ambassador independently for
every Emissary you use:  

```
import { ambassador, discordEmissary } from '@nonsensecodes/ambassador';

discordEmissary.populateDiscordEmissary(
{
  clientID: client_id,
  clientSecret: client_secret,
  authorizeURL: url,
  accessTokenURL: url,
  callbackURL: callback
}, function verify(req, profile)
{
  // final function before serialization
});

ambassador.use(discordEmissary);
```

Currently, `discordEmissary` and `OAuth2Emissary` are available.  

#### Sessions  

ambassador will maintain persistent login sessions.  In order for persistent
sessions to work, the authenticated user must be serialized to the session,
and deserialized when subsequent requests are made. ambassador does not
impose any restrictions on how your user records are stored. Instead, you
provide functions to ambassador which implements the necessary serialization
and deserialization logic.  In a typical application, this will be as simple
as serializing the user ID, and finding the user by ID when deserializing.  

```
ambassador.serializeUser(function(user, done) {
  done(null, user.id);
});

ambassador.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
```

*This is currently a work in progress, as all callbacks will be eliminated
from the library upon completion.*  

#### Middleware  

To use ambassador with [Express](http://expressjs.com/),
configure it with the required `ambassador.initialize()` and
`ambassador.session()`. Make sure [Express Sessions](https://github.com/expressjs/session)
is included and configured properly. Be sure to call ambassador after.  

```
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(config.cookieSecret));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session(
{
  name: 'app name for cookie',
  secret: cookieSecret,
  cookie:
  {
    domain: 'your-domain-here',
    httpOnly: false,
    secure: true,
    maxAge: 3600000,
    sameSite: 'strict'
  },
  store: store,
  resave: false,
  saveUninitialized: false
}));
app.use(ambassador.initialize());
app.use(ambassador.session());

```

Your `session` settings may differ. This is just an example.  

#### Authenticate Requests  

ambassador provides an `authenticate()` function, which is used as route
middleware to authenticate requests.  

```
app.post('/login', 
  ambassador.authenticate('OAuth2', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/account');
  });
```

#### State  

Due to the inconsistent manner in which [Express Sessions](https://github.com/expressjs/session)
manages cookies, state is managed by passing the original cookie id as the
state parameter on outgoing OAuth requests, and is used to retrieve the same
cookie from the store upon return. If the request was tampered with and the
cookie cannot be found (because the state and cookie id don't match), the
authentication fails and the user is not logged in. As such, you will need
to include logic to retrieve the cookie on your route as part of your
middleware before continuing to claim the access token:  

```
app.get('/callback', (req, res, next) => {
  store.get(req.query.state, function storeGetCallback(err, session)
  {
    if (err) {
      return console.error(err);
    }
    next();
  });
}, ambassador.authenticate('OAuth2'));

```

`store.get` is a function of Express Sessions and requires a session ID and
a callback function as parameters. By reason of the way state is handled, I
recommend having two routes to manage authenticating a user: one route to
initiate the authentication, and a second to serve the callback and handle
the authorization code.  

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
