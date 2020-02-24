import { OAuth2Client } from '../oauth2/rfc6749/client';
import cryptoRandomString from 'crypto-random-string';
import { OAuth2Server } from '../oauth2/rfc6749/server';
import { ClientCredentials } from '../oauth2/rfc6749/common';

class Client implements OAuth2Client {
  authorizationCodeExpires!: number;
  clientId!: string;
  name!: string;
  redirectUris!: string[];
  refreshTokenExpires!: number;
  scopeSupported!: string[];
  tokenExpires!: number;
  tokenTypesSupported!: string[];

  generateAccessToken(): string {
    return cryptoRandomString({
      length: 20,
    });
  }

  generateAuthorizationCode(): string {
    return cryptoRandomString({
      length: 16,
    });
  }

  generateRefreshToken(): string {
    return cryptoRandomString({
      length: 16,
    });
  }

  verifyAuthorizationCode(code: string): string {
    return code;
  }

  verifyRedirectUri(redirectUri: string): string {
    return redirectUri;
  }

  verifyRefreshToken(refreshToken: string): string {
    return refreshToken;
  }

  verifyScope(scope: string): string {
    return scope;
  }
}

export class Server extends OAuth2Server {
  authenticateClient(clientCredentials: ClientCredentials): OAuth2Client {
    const client = new Client();
    client.clientId = clientCredentials.clientId!;
    return client;
  }

  authenticateResourceOwner(username: string, password: string): void {}

  verifyClient(clientId: string): OAuth2Client {
    const client = new Client();
    client.clientId = clientId;
    client.tokenExpires = 600;
    return client;
  }
}
