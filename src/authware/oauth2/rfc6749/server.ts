import { Grant } from './grants/base';
import { ResourceOwnerPasswordCredentialsGrant } from './grants/resource-owner-password-credentials';
import { ClientCredentialsGrant } from './grants/client-credentials';
import { ImplicitGrant } from './grants/implicit';
import { AuthorizationCodeGrant } from './grants/authorization-code';
import { isEmpty } from 'lodash';
import {
  ClientCredentials,
  GrantType,
  OAuth2Request,
  OAuth2Response,
  ResponseType,
} from './common';
import { OAuth2Client } from './client';
import { parse } from 'basic-auth';
import { ErrorName, OAuth2Error } from './errors';

export abstract class OAuth2Server {
  authorizationEndpoints: { [responseType: string]: Grant } = {};
  tokenEndpoints: { [grantType: string]: Grant } = {};
  clientCredentialsExtractors: ClientCredentialsExtractor[] = [];

  constructor() {
    this.enableClientCredentialsExtractor(new BasicAuthClientExtractor());
    this.enableClientCredentialsExtractor(
      new RequestParametersClientCredentialExtractor(),
    );
  }

  authorize(request: OAuth2Request, response: OAuth2Response) {
    const responseType = request.query.response_type;
    const endpoint = this.authorizationEndpoints[responseType];
    if (!endpoint) {
      response.status = 500;
      response.body = 'No authorization endpoint is registered';
      return;
    }
    try {
      endpoint.authorize(request, response);
    } catch (e) {
      endpoint.handleAuthorizationError(request, response, e);
    }
  }

  token(request: OAuth2Request, response: OAuth2Response) {
    const grant_type = request.body.grant_type;
    const endpoint = this.tokenEndpoints[grant_type];
    if (!endpoint) {
      response.status = 500;
      response.body = 'No token endpoint is registered';
      return;
    }
    try {
      endpoint.token(request, response);
    } catch (e) {
      endpoint.handleTokenError(request, response, e);
    }
  }

  enableGrant(grant: Grant) {
    grant.enabledByServer(this);
    const responseType = grant.canHandleResponseType();
    if (responseType) {
      this.registerGrantForAuthorizationEndpoint(responseType, grant);
    }
    const grantType = grant.canHandleGrantType();
    if (grantType) {
      this.registerGrantForTokenEndpoint(grantType, grant);
    }
  }

  enableStandardGrants() {
    const authorizationCodeGrant = new AuthorizationCodeGrant();
    const implicitGrant = new ImplicitGrant();
    const resourceOwnerPasswordCredentialsGrant = new ResourceOwnerPasswordCredentialsGrant();
    const clientCredentialsGrant = new ClientCredentialsGrant();
    const refreshTokenGrant = new ClientCredentialsGrant();
    this.enableGrant(authorizationCodeGrant);
    this.enableGrant(implicitGrant);
    this.enableGrant(clientCredentialsGrant);
    this.enableGrant(resourceOwnerPasswordCredentialsGrant);
    this.enableGrant(refreshTokenGrant);
  }

  enableClientCredentialsExtractor(extractor: ClientCredentialsExtractor) {
    this.clientCredentialsExtractors.push(extractor);
  }

  private registerGrantForAuthorizationEndpoint(
    responseType: ResponseType,
    grant: Grant,
  ) {
    this.authorizationEndpoints[responseType] = grant;
  }

  private registerGrantForTokenEndpoint(grantType: GrantType, grant: Grant) {
    this.tokenEndpoints[grantType] = grant;
  }

  abstract verifyClient(clientId: string): OAuth2Client;

  abstract authenticateClient(
    clientCredentials: ClientCredentials,
  ): OAuth2Client;

  authenticateClient0(request: OAuth2Request): OAuth2Client {
    for (const extractor of this.clientCredentialsExtractors) {
      const clientCredentials = extractor.extract(request);
      if (!isEmpty(clientCredentials)) {
        return this.authenticateClient(clientCredentials);
      }
    }
    throw new OAuth2Error(ErrorName.INVALID_CLIENT);
  }

  abstract authenticateResourceOwner(username: string, password: string): void;
}

export interface ClientCredentialsExtractor {
  extract(request: OAuth2Request): ClientCredentials;
}

export class BasicAuthClientExtractor implements ClientCredentialsExtractor {
  extract(request: OAuth2Request): ClientCredentials {
    const authorizationHeader = request.headers.Authorization;
    const user = parse(authorizationHeader);
    if (user) {
      return {
        clientId: user.name,
        clientSecret: user.pass,
      };
    }
    return {};
  }
}

export class RequestParametersClientCredentialExtractor
  implements ClientCredentialsExtractor {
  extract(request: OAuth2Request): ClientCredentials {
    const clientId = request.body.client_id;
    const clientSecret = request.body.client_secret;
    return { clientId, clientSecret };
  }
}
