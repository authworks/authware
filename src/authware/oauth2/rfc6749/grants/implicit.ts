import { OAuth2Request, OAuth2Response } from '../server';
import { Grant } from './base';

export class ImplicitGrant extends Grant {
  // ===============Request==============
  // response_type
  //      REQUIRED.  Value MUST be set to "token".
  //
  // client_id
  //      REQUIRED.  The client identifier as described in Section 2.2.
  //
  // redirect_uri
  //      OPTIONAL.  As described in Section 3.1.2.
  //
  // scope
  //      OPTIONAL.  The scope of the access request as described by
  //      Section 3.3.
  //
  // state
  //      RECOMMENDED.  An opaque value used by the client to maintain
  //      state between the request and callback.  The authorization
  //      server includes this value when redirecting the user-agent back
  //      to the client.  The parameter SHOULD be used for preventing
  //      cross-site request forgery as described in Section 10.12.
  //
  // The client directs the resource owner to the constructed URI using an
  // HTTP redirection response, or by other means available to it via the
  // user-agent.
  //
  // For example, the client directs the user-agent to make the following
  // HTTP request using TLS (with extra line breaks for display purposes
  // only):
  //
  // GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
  //     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
  // Host: server.example.com
  // ============Response==============
  // - access_token
  // REQUIRED.  The access token issued by the authorization server.
  //
  // - token_type
  // REQUIRED.  The type of the token issued as described in
  // Section 7.1.  Value is case insensitive.
  //
  // - expires_in
  // RECOMMENDED.  The lifetime in seconds of the access token.  For
  // example, the value "3600" denotes that the access token will
  // expire in one hour from the time the response was generated.
  // If omitted, the authorization server SHOULD provide the
  // expiration time via other means or document the default value.
  //
  // - scope
  // OPTIONAL, if identical to the scope requested by the client;
  // otherwise, REQUIRED.  The scope of the access token as
  // described by Section 3.3.
  //
  // - state
  // REQUIRED if the "state" parameter was present in the client
  // authorization request.  The exact value received from the
  // client.
  //
  // The authorization server MUST NOT issue a refresh token.
  //
  // For example, the authorization server redirects the user-agent by
  // sending the following HTTP response (with extra line breaks for
  // display purposes only):
  //
  // HTTP/1.1 302 Found
  // Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
  // &state=xyz&token_type=example&expires_in=3600
  authorize(request: OAuth2Request, response: OAuth2Response) {
    const clientId = this.server.verifyClientId(request.query.client_id);
    const redirectUri = this.server.verifyRedirectUri(
      request.query.redirect_uri,
    );
    const scope = this.server.verifyScope(request.query.scope);
    const state = request.query.state;
    response.redirect(redirectUri, {
      access_token: this.server.generateToken(clientId, ''),
      token_type: 'Bearer',
      expires_in: String(this.server.tokenExpires(request.query.clientId)),
      scope,
      state,
    });
  }

  token(request: OAuth2Request, response: OAuth2Response) {
    throw new Error('A bug: implicit grant should not request token endpoint');
  }
}
