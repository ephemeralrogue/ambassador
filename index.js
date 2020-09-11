// Load modules.
import authenticator from './lib/authenticator.js';
import OAuth2Emissary from './lib/emissaries/oauth2.js';
import discordEmissary from './lib/emissaries/discord.js';

const ambassador = Object.create(authenticator);
ambassador._populateAuthenticator();

export {
  ambassador,
  OAuth2Emissary,
  discordEmissary
};
