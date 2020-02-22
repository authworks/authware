import { ErrorName, OAuth2Error } from '../errors';
import { OAuth2Request, OAuth2Response, OAuth2Server } from '../server';

export abstract class Grant {
  server: OAuth2Server;
  verifyTokenEndpointHttpMethod(request: OAuth2Request) {
    if (request.method !== 'POST') {
      throw new OAuth2Error(ErrorName.ACCESS_DENIED);
    }
  }

  constructor(server: OAuth2Server) {
    this.server = server;
  }
  abstract authorize(request: OAuth2Request, response: OAuth2Response): void;

  abstract token(request: OAuth2Request, response: OAuth2Response): void;

  // - error
  // REQUIRED.  A single ASCII [USASCII] error code from the
  // following:
  //
  // * invalid_request
  // The request is missing a required parameter, includes an
  // invalid parameter value, includes a parameter more than
  // once, or is otherwise malformed.
  //
  // * unauthorized_client
  // The client is not authorized to request an authorization
  // code using this method.
  //
  // * access_denied
  // The resource owner or authorization server denied the
  // request.
  //
  // * unsupported_response_type
  // The authorization server does not support obtaining an
  // authorization code using this method.
  //
  // * invalid_scope
  // The requested scope is invalid, unknown, or malformed.
  //
  // * server_error
  // The authorization server encountered an unexpected
  // condition that prevented it from fulfilling the request.
  // (This error code is needed because a 500 Internal Server
  // Error HTTP status code cannot be returned to the client
  // via an HTTP redirect.)
  //
  // * temporarily_unavailable
  // The authorization server is currently unable to handle
  // the request due to a temporary overloading or maintenance
  // of the server.  (This error code is needed because a 503
  // Service Unavailable HTTP status code cannot be returned
  // to the client via an HTTP redirect.)
  //
  // Values for the "error" parameter MUST NOT include characters
  // outside the set %x20-21 / %x23-5B / %x5D-7E.
  //
  // - error_description
  // OPTIONAL.  Human-readable ASCII [USASCII] text providing
  // additional information, used to assist the client developer in
  // understanding the error that occurred.
  // Values for the "error_description" parameter MUST NOT include
  // characters outside the set %x20-21 / %x23-5B / %x5D-7E.
  //
  // - error_uri
  // OPTIONAL.  A URI identifying a human-readable web page with
  // information about the error, used to provide the client
  // developer with additional information about the error.
  // Values for the "error_uri" parameter MUST conform to the
  // URI-reference syntax and thus MUST NOT include characters
  // outside the set %x21 / %x23-5B / %x5D-7E.
  //
  // - state
  // REQUIRED if a "state" parameter was present in the client
  // authorization request.  The exact value received from the
  // client.
  //
  // For example, the authorization server redirects the user-agent by
  // sending the following HTTP response:
  //
  // HTTP/1.1 302 Found
  // Location: https://client.example.com/cb?error=access_denied&state=xyz
  handleAuthorizationError(
    request: OAuth2Request,
    response: OAuth2Response,
    error: OAuth2Error,
  ) {
    response.redirect(request.query.redirect_uri, {
      error: error.error,
      error_description: error.description,
      error_uri: error.uri,
      state: request.query.state,
    });
  }
  // - error
  // REQUIRED.  A single ASCII [USASCII] error code from the
  // following:
  //
  // * invalid_request
  // The request is missing a required parameter, includes an
  // unsupported parameter value (other than grant type),
  // repeats a parameter, includes multiple credentials,
  // utilizes more than one mechanism for authenticating the
  // client, or is otherwise malformed.
  //
  // * invalid_client
  // Client authentication failed (e.g., unknown client, no
  // client authentication included, or unsupported
  // authentication method).  The authorization server MAY
  // return an HTTP 401 (Unauthorized) status code to indicate
  // which HTTP authentication schemes are supported.  If the
  // client attempted to authenticate via the "Authorization"
  // request header field, the authorization server MUST
  // respond with an HTTP 401 (Unauthorized) status code and
  // include the "WWW-Authenticate" response header field
  // matching the authentication scheme used by the client.
  //
  // * invalid_grant
  // The provided authorization grant (e.g., authorization
  // code, resource owner credentials) or refresh token is
  // invalid, expired, revoked, does not match the redirection
  // URI used in the authorization request, or was issued to
  // another client.
  //
  // * unauthorized_client
  // The authenticated client is not authorized to use this
  // authorization grant type.
  //
  // * unsupported_grant_type
  // The authorization grant type is not supported by the
  // authorization server.
  //
  // * invalid_scope
  // The requested scope is invalid, unknown, malformed, or
  // exceeds the scope granted by the resource owner.
  //
  // Values for the "error" parameter MUST NOT include characters
  // outside the set %x20-21 / %x23-5B / %x5D-7E.
  //
  // * error_description
  // OPTIONAL.  Human-readable ASCII [USASCII] text providing
  // additional information, used to assist the client developer in
  // understanding the error that occurred.
  // Values for the "error_description" parameter MUST NOT include
  // characters outside the set %x20-21 / %x23-5B / %x5D-7E.
  //
  // * error_uri
  // OPTIONAL.  A URI identifying a human-readable web page with
  // information about the error, used to provide the client
  // developer with additional information about the error.
  // Values for the "error_uri" parameter MUST conform to the
  // URI-reference syntax and thus MUST NOT include characters
  // outside the set %x21 / %x23-5B / %x5D-7E.
  //
  // The parameters are included in the entity-body of the HTTP response
  // using the "application/json" media type as defined by [RFC4627].  The
  // parameters are serialized into a JSON structure by adding each
  // parameter at the highest structure level.  Parameter names and string
  // values are included as JSON strings.  Numerical values are included
  // as JSON numbers.  The order of parameters does not matter and can
  // vary.
  //
  // For example:
  //
  // HTTP/1.1 400 Bad Request
  // Content-Type: application/json;charset=UTF-8
  // Cache-Control: no-store
  // Pragma: no-cache
  //
  // {
  // "error":"invalid_request"
  // }
  handleTokenError(
    request: OAuth2Request,
    response: OAuth2Response,
    error: OAuth2Error,
  ) {
    response.sendJson(
      {
        error: error.error,
        error_description: error.description,
        error_uri: error.uri,
      },
      error.status,
    );
  }
}
