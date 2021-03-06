import { Grant } from './base';
import {
  GrantType,
  OAuth2Request,
  OAuth2Response,
  ResponseType,
} from '../common';

export class ClientCredentialsGrant extends Grant {
  canHandleResponseType(): ResponseType | false {
    return false;
  }

  canHandleGrantType(): GrantType | false {
    return GrantType.CLIENT_CREDENTIALS;
  }

  authorize(request: OAuth2Request, response: OAuth2Response) {
    throw new Error(
      'A bug: client credentials grant should not request authorization endpoint',
    );
  }

  // ============Request=============
  // grant_type
  // REQUIRED.  Value MUST be set to "client_credentials".
  //
  // scope
  // OPTIONAL.  The scope of the access request as described by
  // Section 3.3.
  //
  // The client MUST authenticate with the authorization server as
  // described in Section 3.2.1.
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
  // grant_type=client_credentials
  // ============Response===========
  // An example successful response:
  //
  //  HTTP/1.1 200 OK
  //  Content-Type: application/json;charset=UTF-8
  //  Cache-Control: no-store
  //  Pragma: no-cache
  //
  //  {
  //    "access_token":"2YotnFZFEjr1zCsicMWpAA",
  //    "token_type":"example",
  //    "expires_in":3600,
  //    "example_parameter":"example_value"
  //  }
  token(request: OAuth2Request, response: OAuth2Response) {
    super.verifyTokenEndpointHttpMethod(request);
    const client = this.server.authenticateClient0(request);
    const clientId = client.clientId;

    response.sendJson({
      access_token: client.generateAccessToken(),
      token_type: 'Bearer',
      expires_in: client.tokenExpires,
    });
  }
}
