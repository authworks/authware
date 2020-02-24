import { OAuth2Request, OAuth2Response } from '../../oauth2/rfc6749/common';
import { Request, Response } from 'express';

type OAuthEndpoint = (req: OAuth2Request, res: OAuth2Response) => void;

export function connect(endpoint: OAuthEndpoint) {
  return (req: Request, res: Response) => {
    const oauthReq = new OAuth2Request(
      // @ts-ignore
      req.method,
      req.url,
      req.headers,
      req.body,
    );
    const oauthRes = new OAuth2Response();
    endpoint(oauthReq, oauthRes);

    for (const key of Object.keys(oauthRes.headers)) {
      res.header(key, oauthRes.headers[key]);
    }
    res.status(oauthRes.status).send(oauthRes.body);
  };
}
