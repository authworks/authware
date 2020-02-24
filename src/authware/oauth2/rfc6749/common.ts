import { parseUrl, stringifyUrl } from 'query-string';

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
  status!: number;
  body!: any | string;
  headers: OAuth2HttpHeaders = {};

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
  PASSWORD = 'password',
  CLIENT_CREDENTIALS = 'client_credentials',
  REFRESH_TOKEN = 'refresh_token',
  DEVICE = 'urn:ietf:params:oauth:grant-type:device_code',
}

export enum ResponseType {
  CODE = 'code',
  TOKEN = 'token',
}

export interface ClientCredentials {
  clientId?: string;
  clientSecret?: string;
}
