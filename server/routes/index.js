const _ = require('lodash');
const router = require('express').Router;
const middlewares = require('auth0-extension-express-tools').middlewares;

const config = require('../lib/config');
const htmlRoute = require('./html');

module.exports = (storage) => {
  const app = router();
  const authenticateAdmins = middlewares.authenticateAdmins({
    credentialsRequired: true,
    secret: config('EXTENSION_SECRET'),
    audience: 'urn:extend-security-extension',
    baseUrl: config('PUBLIC_WT_URL') || config('WT_URL'),
    onLoginSuccess: (req, res, next) => next()
  });

  app.get('/', htmlRoute());

  return app;
};
