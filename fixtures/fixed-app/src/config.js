// Values are loaded from the environment; nothing sensitive is stored in this file.
module.exports = {
  port: Number(process.env.PORT) || 3000,
  apiKey: process.env.API_KEY,
  sessionToken: process.env.SESSION_TOKEN,
};
