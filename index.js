// Load modules.
import authenticator from './lib/authenticator.js';
import OAuth2Strategy from './lib/oauth2strategy.js';

const ambassador = Object.create(authenticator);
ambassador.buildAuthenticator();

export { ambassador, OAuth2Strategy };