import {
  GrantType,
  OAuth2Request,
  OAuth2Response,
  ResponseType,
} from '../common';
import { Grant } from './base';

export class ResourceOwnerPasswordCredentialsGrant extends Grant {
  canHandleResponseType(): ResponseType | false {
    return false;
  }

  canHandleGrantType(): false | GrantType {
    return GrantType.PASSWORD;
  }

  authorize(request: OAuth2Request, response: OAuth2Response) {
    throw new Error(
      'A bug: resource owner password credentials grant should not request authorization endpoint',
    );
  }

  // =============Request===============
  // grant_type
  // REQUIRED.  Value MUST be set to "password".
  //
  // username
  // REQUIRED.  The resource owner username.
  //
  // password
  // REQUIRED.  The resource owner password.
  //
  // scope
  // OPTIONAL.  The scope of the access request as described by
  // Section 3.3.
  //
  // If the client type is confidential or the client was issued client
  // credentials (or assigned other authentication requirements), the
  // client MUST authenticate with the authorization server as described
  // in Section 3.2.1.
  //
  // For example, the client makes the following HTTP request using
  // transport-layer security (with extra line breaks for display purposes
  // only):
  //
  // POST /token HTTP/1.1
  // Host: server.example.com
  // Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
  // Content-Type: application/x-www-form-urlencoded
  //
  // grant_type=password&username=johndoe&password=A3ddj3w
  // =============Response==============
  //   An example successful response:
  //
  //   HTTP/1.1 200 OK
  //   Content-Type: application/json;charset=UTF-8
  //   Cache-Control: no-store
  //   Pragma: no-cache
  //
  // {
  //   "access_token":"2YotnFZFEjr1zCsicMWpAA",
  //   "token_type":"example",
  //   "expires_in":3600,
  //   "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  //   "example_parameter":"example_value"
  // }
  token(request: OAuth2Request, response: OAuth2Response) {
    super.verifyTokenEndpointHttpMethod(request);
    const client = this.server.authenticateClient0(request);
    const clientId = client.clientId;
    const username = request.body.username;
    const password = request.body.password;
    this.server.authenticateResourceOwner(username, password);
    const scope = client.verifyScope(request.body.scope);
    response.sendJson({
      access_token: client.generateAccessToken(),
      token_type: 'Bearer',
      expires_in: client.tokenExpires,
      refresh_token: client.generateRefreshToken(),
    });
  }
}
