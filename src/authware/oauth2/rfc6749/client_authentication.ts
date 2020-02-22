import { OAuth2Request, OAuth2Server } from './server';
import { parse } from 'basic-auth';
import { ErrorName, OAuth2Error } from './errors';

export interface ClientAuthentication {
  authenticateClient(request: OAuth2Request): string;
}

export class BasicAuthClientAuthentication implements ClientAuthentication {
  server: OAuth2Server;
  constructor(server: OAuth2Server) {
    this.server = server;
  }
  authenticateClient(request: OAuth2Request): string {
    const authorizationHeader = request.headers.Authorization;
    const user = parse(authorizationHeader);
    if (user) {
      const clientId = user.name;
      const clientSecret = user.pass;
      this.server.authenticateClient(clientId, clientSecret);
      return clientId;
    }
    throw new OAuth2Error(ErrorName.INVALID_CLIENT);
  }
}
