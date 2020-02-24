import { OAuth2Server } from './server';
import { parse } from 'basic-auth';
import { ErrorName, OAuth2Error } from './errors';
import { OAuth2Request } from './common';
import { OAuth2Client } from './client';

export abstract class ClientAuthentication {
  server: OAuth2Server;
  constructor(server: OAuth2Server) {
    this.server = server;
  }
  abstract authenticateClient(request: OAuth2Request): OAuth2Client;
}

export class BasicAuthClientAuthentication extends ClientAuthentication {
  authenticateClient(request: OAuth2Request): OAuth2Client {
    const authorizationHeader = request.headers.Authorization;
    const user = parse(authorizationHeader);
    if (user) {
      const clientId = user.name;
      const clientSecret = user.pass;
      return this.server.authenticateClient(clientId, clientSecret);
    }
    throw new OAuth2Error(ErrorName.INVALID_CLIENT);
  }
}

export class RequestParametersClientAuthentication extends ClientAuthentication {
  authenticateClient(request: OAuth2Request): OAuth2Client {
    const clientId = request.body.client_id;
    const clientSecret = request.body.client_secret;
    return this.server.authenticateClient(clientId, clientSecret);
  }
}
