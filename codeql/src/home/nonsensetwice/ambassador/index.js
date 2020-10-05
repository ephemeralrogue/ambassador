// Load modules.
import authenticator from './lib/authenticator.js';
import OAuth2Ambassador from './lib/ambassadors/oauth2.js';
import discordAmbassador from './lib/ambassadors/discord.js';

const ambassador = Object.create(authenticator);
ambassador.buildAuthenticator();

export {
  ambassador,
  OAuth2Ambassador,
  discordAmbassador
};
