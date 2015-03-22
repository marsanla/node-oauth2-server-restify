/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var auth = require('basic-auth'),
    error = require('node-restify-errors'),
    runner = require('./runner'),
    token = require('./token');

module.exports = Grant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  extractCredentials,
  checkClient,
  checkGrantTypeAllowed,
  checkGrantType,
  generateAccessToken,
  saveAccessToken,
  generateRefreshToken,
  saveRefreshToken,
  sendResponse
];

/**
 * Grant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Grant (config, req, res, next) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();
  this.req = req;
  this.res = res;

  runner(fns, this, next);
}

/**
 * Basic request validation and extraction of grant_type and client creds
 *
 * @param  {Function} next
 * @this   OAuth
 */
function extractCredentials (next) {
  // Only POST via application/x-www-form-urlencoded is acceptable
  if (this.req.method !== 'POST' ||
      !this.req.is('application/x-www-form-urlencoded')) {
    return next(new error.BadMethodError('Method must be POST with application/x-www-form-urlencoded encoding'));
  }

  // Grant type
  this.grantType = this.req.params && this.req.params.grant_type;
  if (!this.grantType || !this.grantType.match(this.config.regex.grantType)) {
    return next(new error.BadMethodError('Invalid or missing grant_type parameter'));
  }

  // Extract credentials
  // http://tools.ietf.org/html/rfc6749#section-3.2.1
  this.client = credsFromBasic(this.req) || credsFromBody(this.req);

  if (!this.client.clientId ||
      !this.client.clientId.match(this.config.regex.clientId)) {
    return next(new error.InvalidCredentialsError('Invalid or missing client_id parameter'));
  } else if (!this.client.clientSecret) {
    return next(new error.InvalidCredentialsError('Missing client_secret parameter'));
  }

  next();
}

/**
 * Client Object (internal use only)
 *
 * @param {String} id     client_id
 * @param {String} secret client_secret
 */
function Client (id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

/**
 * Extract client creds from Basic auth
 *
 * @return {Object} Client
 */
function credsFromBasic (req) {
  var user = auth(req);

  if (!user) return false;

  return new Client(user.name, user.pass);
}

/**
 * Extract client creds from body
 *
 * @return {Object} Client
 */
function credsFromBody (req) {
  return new Client(req.params.client_id, req.params.client_secret);
}

/**
 * Check extracted client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkClient (next) {
  this.model.getClient(this.client.clientId, this.client.clientSecret,
      function (err, client) {
        if (err) return next(new error.InternalError(err));

        if (!client) {
          return next(new error.InvalidCredentialsError('Client credentials are invalid'));
        }

        next();
      });
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkGrantType (next) {
  if (this.grantType.match(/^http(s|):\/\//) && this.model.extendedGrant) {
    return useExtendedGrant.call(this, next);
  }

  switch (this.grantType) {
    case 'authorization_code':
      return useAuthCodeGrant.call(this, next);
    case 'password':
      return usePasswordGrant.call(this, next);
    case 'refresh_token':
      return useRefreshTokenGrant.call(this, next);
    case 'client_credentials':
      return useClientCredentialsGrant.call(this, next);
    default:
      next(new error.MissingParameterError('Invalid grant_type parameter or parameter missing'));
  }
}

/**
 * Grant for authorization_code grant type
 *
 * @param  {Function} next
 */
function useAuthCodeGrant (next) {
  var code = this.req.params.code;

  if (!code) {
    return next(new error.MissingParameterError('No "code" parameter'));
  }

  var self = this;
  this.model.getAuthCode(code, function (err, authCode) {
    if (err) return next(new error('server_error', false, err));

    if (!authCode || authCode.clientId !== self.client.clientId) {
      return next(new error.InvalidContentError('Invalid code'));
    } else if (authCode.expires < self.now) {
      return next(new error.InvalidContentError('Code has expired'));
    }

    self.user = authCode.user || { id: authCode.userId };
    if (!self.user.id) {
      return next(new error.InternalError('No user/userId parameter returned from getauthCode'));
    }

    next();
  });
}

/**
 * Grant for password grant type
 *
 * @param  {Function} next
 */
function usePasswordGrant (next) {
  // User credentials
  var uname = this.req.params.username,
      pword = this.req.params.password;
  if (!uname || !pword) {
    return next(new error.InvalidCredentialsError('Missing parameters. "username" and "password" are required'));
  }

  var self = this;
  return this.model.getUser(uname, pword, function (err, user) {
    if (err) return next(new error.InternalError(err));
    if (!user) {
      return next(new error.InvalidCredentialsError('User credentials are invalid'));
    }

    self.user = user;
    next();
  });
}

/**
 * Grant for refresh_token grant type
 *
 * @param  {Function} next
 */
function useRefreshTokenGrant (next) {
  var token = this.req.params.refresh_token;

  if (!token) {
    return next(new error.BadMethodError('No "refresh_token" parameter'));
  }

  var self = this;
  this.model.getRefreshToken(token, function (err, refreshToken) {
    if (err) return next(new error.InternalError(err));

    if (!refreshToken || refreshToken.clientId !== self.client.clientId) {
      return next(new error.BadMethodError('Invalid refresh token'));
    } else if (refreshToken.expires !== null &&
        refreshToken.expires < self.now) {
      return next(new error.BadMethodError('Refresh token has expired'));
    }

    if (!refreshToken.user && !refreshToken.userId) {
      return next(new error.InternalError('No user/userId parameter returned from getRefreshToken'));
    }

    self.user = refreshToken.user || { id: refreshToken.userId };

    if (self.model.revokeRefreshToken) {
      return self.model.revokeRefreshToken(token, function (err) {
        if (err) return next(new error.InternalError(err));
        next();
      });
    }

    next();
  });
}

/**
 * Grant for client_credentials grant type
 *
 * @param  {Function} next
 */
function useClientCredentialsGrant (next) {
  // Client credentials
  var clientId = this.client.clientId,
      clientSecret = this.client.clientSecret;

  if (!clientId || !clientSecret) {
    return next(new error.InvalidCredentialsError('Missing parameters. "client_id" and "client_secret" are required'));
  }

  var self = this;
  return this.model.getUserFromClient(clientId, clientSecret,
      function (err, user) {
        if (err) return next(new error.InternalError(err));
        if (!user) {
          return next(new error.InvalidCredentialsError('Client credentials are invalid'));
        }

        self.user = user;
        next();
      });
}

/**
 * Grant for extended (http://*) grant type
 *
 * @param  {Function} next
 */
function useExtendedGrant (next) {
  var self = this;
  this.model.extendedGrant(this.grantType, this.req,
      function (err, supported, user) {
        if (err) {
          return next(new error(err.error || 'server_error',
              err.description || err.message, err));
        }

        if (!supported) {
          return next(new error.BadMethodError('Invalid grant_type parameter or parameter missing'));
        } else if (!user || user.id === undefined) {
          return next(new error.BadMethodError('Invalid request.'));
        }

        self.user = user;
        next();
      });
}

/**
 * Check the grant type is allowed for this client
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkGrantTypeAllowed (next) {
  this.model.grantTypeAllowed(this.client.clientId, this.grantType,
      function (err, allowed) {
        if (err) return next(new error.InternalError(err));

        if (!allowed) {
          return next(new error.InvalidCredentialsError('The grant type is unauthorised for this client_id'));
        }

        next();
      });
}

/**
 * Generate an access token
 *
 * @param  {Function} next
 * @this   OAuth
 */
function generateAccessToken (next) {
  var self = this;
  token(this, 'accessToken', function (err, token) {
    self.accessToken = token;
    next(err);
  });
}

/**
 * Save access token with model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function saveAccessToken (next) {
  var accessToken = this.accessToken;

  // Object indicates a reissue
  if (typeof accessToken === 'object' && accessToken.accessToken) {
    this.accessToken = accessToken.accessToken;
    return next();
  }

  var expires = null;
  if (this.config.accessTokenLifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.config.accessTokenLifetime);
  }

  this.model.saveAccessToken(accessToken, this.client.clientId, expires,
      this.user, function (err, token) {
        if (err) return next(new error.InternalError(err));
        next();
      });
}

/**
 * Generate a refresh token
 *
 * @param  {Function} next
 * @this   OAuth
 */
function generateRefreshToken (next) {
  if (this.config.grants.indexOf('refresh_token') === -1) return next();

  var self = this;
  token(this, 'refreshToken', function (err, token) {
    self.refreshToken = token;
    next(err);
  });
}

/**
 * Save refresh token with model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function saveRefreshToken (next) {
  var refreshToken = this.refreshToken;

  if (!refreshToken) return next();

  // Object indicates a reissue
  if (typeof refreshToken === 'object' && refreshToken.refreshToken) {
    this.refreshToken = refreshToken.refreshToken;
    return next();
  }

  var expires = null;
  if (this.config.refreshTokenLifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.config.refreshTokenLifetime);
  }

  this.model.saveRefreshToken(refreshToken, this.client.clientId, expires,
      this.user, function (err, user) {
        if (err) return next(new error.InternalError(err));
        next();
      });
}

/**
 * Create an access token and save it with the model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function sendResponse (next) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };

  if (this.config.accessTokenLifetime !== null) {
    response.expires_in = this.config.accessTokenLifetime;
  }

  if (this.refreshToken) response.refresh_token = this.refreshToken;

  this.res
      .set('Cache-Control', 'no-store')
      .set('Pragma', 'no-cache')
      .send(response);

  if (this.config.continueAfterResponse)
    next();
}
