import { Grant } from './base';
import {
  GrantType,
  OAuth2Request,
  OAuth2Response,
  ResponseType,
} from '../common';

export class RefreshTokenGrant extends Grant {
  canHandleResponseType(): ResponseType | false {
    return false;
  }

  canHandleGrantType(): GrantType | false {
    return GrantType.REFRESH_TOKEN;
  }

  authorize(request: OAuth2Request, response: OAuth2Response): void {
    throw new Error(
      'A bug: refresh token grant should not request authorization endpoint',
    );
  }

  token(request: OAuth2Request, response: OAuth2Response): void {
    super.verifyTokenEndpointHttpMethod(request);
    const client = this.server.verifyClient(request.body.client_id);
    const clientId = client.clientId;
    const refreshToken = client.verifyRefreshToken(request.body.refresh_token);
    const scope = client.verifyScope(request.body.scope);
    response.sendJson({
      access_token: client.generateAccessToken(),
      token_type: 'Bearer',
      expires_in: client.tokenExpires,
      refresh_token: client.generateRefreshToken(),
    });
  }
}
