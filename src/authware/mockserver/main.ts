import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import { connect } from '../integration/express';
import { Server } from './oauth.provider';

const app = express();
app.use(bodyParser.json());
const server = new Server();
server.enableStandardGrants();

app.get('/authorize', connect(server.authorize.bind(server)));
app.post('/token', connect(server.token.bind(server)));
app.get('/cb', (req, res) => {
  res.send(req.url);
});

app.listen(8080);
