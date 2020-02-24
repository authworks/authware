import { Grant } from '../../rfc6749/grants/base';
import {
  GrantType,
  OAuth2Request,
  OAuth2Response,
  ResponseType,
} from '../../rfc6749/common';

export class AuthorizationCodeWithPKCEGrant extends Grant {
  canHandleResponseType(): ResponseType | false {
    return ResponseType.CODE;
  }

  canHandleGrantType(): GrantType | false {
    return GrantType.AUTHORIZATION_CODE;
  }

  authorize(request: OAuth2Request, response: OAuth2Response): void {}

  token(request: OAuth2Request, response: OAuth2Response): void {}
}
