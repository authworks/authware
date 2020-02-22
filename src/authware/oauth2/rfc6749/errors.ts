import { stringify } from 'query-string';
// export class AuthwareBaseError extends Error {
//   // short error description
//   error: string;
//   // long-string to describe this error
//   description?: string;
//   // web page that describes this error
//   uri?: string;
//   constructor(error: string, description?: string, uri?: string) {
//     super(`${error}: ${description}`);
//     this.uri = uri;
//     this.error = error;
//     this.description = description;
//   }
// }
//
// export class AuthwareHttpError extends AuthwareBaseError {
//   status: number;
//   constructor(error: string, description?: string, uri?: string, status = 400) {
//     super(error, description, uri);
//     this.status = status;
//   }
//
//   getBody(): { [key: string]: string } {
//     const errorBody: { [key: string]: string } = { error: this.error };
//     if (this.description) {
//       errorBody.error_description = this.description;
//     }
//     if (this.uri) {
//       errorBody.error_uri = this.uri;
//     }
//     return errorBody;
//   }
// }
//
// export class OAuth2Error extends AuthwareHttpError {
//   redirectUri?: string;
//   redirectFragment?: boolean;
//   constructor(
//     error: string,
//     description?: string,
//     uri?: string,
//     status = 400,
//     redirectUri?: string,
//     redirectFragment = false,
//   ) {
//     super(error, description, uri, status);
//     this.redirectUri = redirectUri;
//     this.redirectFragment = redirectFragment;
//   }
//
//   getBody(): { [p: string]: string } {
//     const body = super.getBody();
//     if (this.redirectUri) {
//       body.redirect_uri = this.redirectUri;
//     }
//     return body;
//   }
// }

export enum ErrorName {
  INSECURE_TRANSPORT,
  INVALID_REQUEST,
  INVALID_CLIENT,
  INVALID_GRANT,
  UNAUTHORIZED_CLIENT,
  UNSUPPORTED_GRANT,
  INVALID_SCOPE,
  ACCESS_DENIED,
  MISSING_AUTHORIZATION,
  UNSUPPORTED_TOKEN_TYPE,
  MISSING_CODE,
  MISSING_TOKEN_TYPE,
  MISMATCHING_STATE,
}

const errors: {
  [key in ErrorName]: {
    error: string;
    description?: string;
    uri?: string;
    status: number;
  };
} = {
  [ErrorName.INSECURE_TRANSPORT]: {
    error: 'insecure_transport',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.INVALID_REQUEST]: {
    error: 'invalid_request',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.INVALID_CLIENT]: {
    error: 'invalid_client',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.INVALID_GRANT]: {
    error: 'invalid_grant',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.UNAUTHORIZED_CLIENT]: {
    error: 'unauthorized_client',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.UNSUPPORTED_GRANT]: {
    error: 'unauthorized_grant',
    description: '',
    uri: '',
    status: 400,
  },
  [ErrorName.INVALID_SCOPE]: {
    error: 'invalid_scope',
    description: 'The requested scope is invalid, unknown, or malformed.',
    uri: '',
    status: 400,
  },
  [ErrorName.ACCESS_DENIED]: {
    error: 'access_denied',
    description:
      'The resource owner or authorization server denied the request',
    uri: '',
    status: 400,
  },
  [ErrorName.MISSING_AUTHORIZATION]: {
    error: 'missing_authorization',
    description: 'Missing "Authorization" in headers.',
    uri: '',
    status: 401,
  },
  [ErrorName.UNSUPPORTED_TOKEN_TYPE]: {
    error: 'missing_token_type',
    description: 'Missing "token_type" in response.',
    uri: '',
    status: 401,
  },
  [ErrorName.MISSING_CODE]: {
    error: 'missing_code',
    description: 'Missing "code" in response.',
    uri: '',
    status: 400,
  },
  [ErrorName.MISSING_TOKEN_TYPE]: {
    error: 'missing_token_type',
    description: 'Missing "token_type" in response.',
    uri: '',
    status: 400,
  },
  [ErrorName.MISMATCHING_STATE]: {
    error: 'mismatching_state',
    description: 'CSRF Warning! State not equal in request and response.',
    uri: '',
    status: 400,
  },
};

export class OAuth2Error extends Error {
  error: string;
  status: number;
  description?: string;
  uri?: string;
  state?: string;
  redirectUri?: string;
  constructor(error: ErrorName, state?: string, redirectUri?: string) {
    const e = errors[error];
    super(`${e.error}: ${e.description}`);
    this.error = e.error;
    this.description = e.description;
    this.uri = e.uri;
    this.status = e.status;
    this.state = state;
    this.redirectUri = redirectUri;
  }

  getEncodedParams() {
    stringify(
      {
        error: this.error,
        error_description: this.description,
        error_uri: this.uri,
        state: this.state,
      },
      {
        sort: false,
        skipNull: true,
      },
    );
  }
}
