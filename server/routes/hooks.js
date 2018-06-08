const router = require('express').Router;
const middlewares = require('auth0-extension-express-tools').middlewares;

const config = require('../lib/config');
const logger = require('../lib/logger');
const Promise = require('bluebird');

module.exports = () => {
  const hooks = router();
  const hookValidator = middlewares
    .validateHookToken(config('AUTH0_DOMAIN'), config('WT_URL'), config('EXTENSION_SECRET'));

  hooks.use('/on-uninstall', hookValidator('/.extensions/on-uninstall'));

  hooks.use('/on-install', hookValidator('/.extensions/on-install'));

  hooks.use(middlewares.managementApiClient({
    domain: config('AUTH0_DOMAIN'),
    clientId: config('AUTH0_CLIENT_ID'),
    clientSecret: config('AUTH0_CLIENT_SECRET')
  }));

  hooks.post('/on-install', (req, res) => {
    const auth0 = req.auth0;
    const identifier = config('API_AUDIENCE');
    const emailOwner = config('OWNER');
    const promises = [
      auth0.clients.create({ name: config('WEBSITE_CLIENT_NAME'), app_type: 'regular_web' }),
      auth0.clients.create({ name: config('EXTEND_DEPLOYMENT_CLIENT'), app_type: 'non_interactive' }),
      auth0.resourceServers.create({
        name: config('API_NAME'),
        identifier: identifier
      }),
      auth0.rules.create({
        name: 'Extend Authorization',
        order: 1,
        enabled: true,
        script: [
          'function (user, context, callback) {',
          '  var crypto = require("crypto");',
          '',
          `  if (context.clientName !== "${config('EXTEND_DEPLOYMENT_CLIENT')}" && context.clientName !== "${config('WEBSITE_CLIENT_NAME')}") {`,
          '    return callback(null, user, context);',
          '  }',
          '',
          '  var audience = (context.request && context.request.query && context.request.query.audience);',
          '',
          `  if (audience !== "${identifier}")`,
          '    return callback(null, user, context);',
          '',
          '  if (!user.email || !user.email_verified) {',
          '    return callback(new UnauthorizedError("User must have verified e-mail address to log in."));',
          '  }',
          '',
          `  if (user.email === "${emailOwner}") {`,
          '    var hash = crypto.createHash("md5").update(user.nickname);',
          '    var container = hash.digest("hex");',
          '    context.accessToken.scope = ["openid", "profile", "wt:owner:" + container];',
          '  }',
          '',
          '  return callback(null, user, context);',
          '}',
        ].join('\n')
      })
    ];

    Promise
      .all(promises)
      .then(() => {
        res.sendStatus(204);
      })
      .catch((err) => {
        console.log(err);
        res.sendStatus(500);
      });
  });

  hooks.delete('/on-uninstall', (req, res) => {
    const clientId = config('AUTH0_CLIENT_ID');
    req.auth0.clients.delete({ client_id: clientId })
      .then(() => {
        logger.debug(`Deleted client ${clientId}`);
        res.sendStatus(204);
      })
      .catch((err) => {
        logger.debug(`Error deleting client: ${config('AUTH0_CLIENT_ID')}`);
        logger.error(err);

        // Even if deleting fails, we need to be able to uninstall the extension.
        res.sendStatus(204);
      });
  });
  return hooks;
};
