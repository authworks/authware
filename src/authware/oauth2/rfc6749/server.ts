import { parseUrl, stringifyUrl } from 'query-string';
import { Grant } from './grants/base';
import { ResourceOwnerPasswordCredentialsGrant } from './grants/resource-owner-password-credentials';
import { ClientCredentialsGrant } from './grants/client-credentials';
import { ImplicitGrant } from './grants/implicit';
import { AuthorizationCodeGrant } from './grants/authorization-code';
import {
  BasicAuthClientAuthentication,
  ClientAuthentication,
} from './client_authentication';

export interface OAuth2HttpHeaders {
  [key: string]: string;
}

export type OAuth2HttpMethod = 'GET' | 'POST';

export class OAuth2Request {
  method: OAuth2HttpMethod;
  uri: string;
  body: any | string;
  headers: OAuth2HttpHeaders = {};
  query: { [key: string]: any } = {};

  constructor(
    method: OAuth2HttpMethod,
    uri: string,
    headers: OAuth2HttpHeaders,
    body: any,
  ) {
    this.method = method;
    this.uri = uri;
    this.headers = headers;
    this.body = body;
    this.query = parseUrl(uri).query;
  }
}

export class OAuth2Response {
  status: number;
  body: any;
  headers: OAuth2HttpHeaders;

  constructor(status: number, headers: OAuth2HttpHeaders, body: any | string) {
    this.status = status;
    this.headers = headers;
    this.body = body;
  }

  redirect(url: string, query: any, status = 302) {
    this.status = status;
    this.headers.Location = stringifyUrl(
      {
        url,
        query,
      },
      {
        sort: false,
        skipNull: true,
      },
    );
  }

  sendJson(body: any, status = 200, noCache = true) {
    this.headers['Content-Type'] = 'application/json;charset=UTF-8';
    if (noCache) {
      this.headers['Cache-Control'] = 'no-store';
      this.headers.Pragma = 'no-cache';
    }
    this.status = status;
    this.body = body;
  }
}

export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  IMPLICIT = 'implicit',
  PASSWORD = 'password',
  CLIENT_CREDENTIALS = 'client_credentials',
}

export enum ResponseType {
  CODE = 'code',
  TOKEN = 'token',
}

export class OAuth2Server {
  authorizationEndpoints: { [responseType: string]: Grant } = {};
  tokenEndpoints: { [grantType: string]: Grant } = {};
  clientAuthentication: ClientAuthentication;

  constructor() {
    this.registerStandardGrants();
    this.clientAuthentication = new BasicAuthClientAuthentication(this);
  }

  authorize(request: OAuth2Request, response: OAuth2Response) {
    const responseType = request.query.response_type;
    const endpoint = this.authorizationEndpoints[responseType];
    try {
      endpoint.authorize(request, response);
    } catch (e) {
      endpoint.handleAuthorizationError(request, response, e);
    }
  }

  token(request: OAuth2Request, response: OAuth2Response) {
    const grant_type = request.query.grant_type;
    const endpoint = this.tokenEndpoints[grant_type];
    try {
      endpoint.token(request, response);
    } catch (e) {
      endpoint.handleTokenError(request, response, e);
    }
  }

  registerStandardGrants() {
    const authorizationCodeGrant = new AuthorizationCodeGrant(this);
    const implicitGrant = new ImplicitGrant(this);
    const resourceOwnerPasswordCredentialsGrant = new ResourceOwnerPasswordCredentialsGrant(
      this,
    );
    const clientCredentialsGrant = new ClientCredentialsGrant(this);
    this.registerGrantForAuthorizationEndpoint(
      ResponseType.CODE,
      authorizationCodeGrant,
    );
    this.registerGrantForAuthorizationEndpoint(
      ResponseType.TOKEN,
      implicitGrant,
    );
    this.registerGrantForTokenEndpoint(
      GrantType.AUTHORIZATION_CODE,
      authorizationCodeGrant,
    );
    this.registerGrantForTokenEndpoint(GrantType.IMPLICIT, implicitGrant);
    this.registerGrantForTokenEndpoint(
      GrantType.PASSWORD,
      resourceOwnerPasswordCredentialsGrant,
    );
    this.registerGrantForTokenEndpoint(
      GrantType.CLIENT_CREDENTIALS,
      clientCredentialsGrant,
    );
  }

  registerGrantForAuthorizationEndpoint(
    responseType: ResponseType,
    grant: Grant,
  ) {
    this.authorizationEndpoints[responseType] = grant;
  }

  registerGrantForTokenEndpoint(grantType: GrantType, grant: Grant) {
    this.authorizationEndpoints[grantType] = grant;
  }

  verifyClientId(clientId: string): string {
    return clientId;
  }

  verifyScope(scope: string): string {
    return scope;
  }

  verifyRedirectUri(redirectUri: string): string {
    return redirectUri;
  }

  verifyAuthorizationCode(code: string): string {
    return code;
  }

  generateToken(clientId: string, grantUser: string): string {
    return '';
  }

  tokenExpires(clientId: string): number {
    return 6000;
  }

  authenticateClient(clientId: string, clientSecret: string): string {
    return clientId;
  }
}
