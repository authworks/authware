export interface OAuth2Client {
  clientId: string;
  name: string;
  scopeSupported: string[];
  tokenTypesSupported: string[];
  tokenExpires: number;
  refreshTokenExpires: number;
  authorizationCodeExpires: number;
  redirectUris: string[];

  verifyScope(scope: string): string;

  verifyRedirectUri(redirectUri: string): string;

  verifyAuthorizationCode(code: string): string;

  verifyRefreshToken(refreshToken: string): string;

  generateAccessToken(): string;

  generateAuthorizationCode(): string;

  generateRefreshToken(): string;
}
