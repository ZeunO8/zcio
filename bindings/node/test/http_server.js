'use strict';

/* Tiny HTTP server for the offline httpGet/httpPost tests. Runs in its own
 * process because zcio's HTTP client is synchronous and would otherwise block
 * the same event loop that serves the request. Prints "PORT <n>" once ready.
 * Sends an explicit Content-Length so responses are not chunk-encoded. */

const http = require('http');

const BODY = 'hello from node http';

function send(res, text) {
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

const srv = http.createServer((req, res) => {
  if (req.method === 'POST' || req.method === 'PUT') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    const verb = req.method.toLowerCase() === 'put' ? 'put' : 'posted';
    req.on('end', () => send(res, verb + ':' + Buffer.concat(chunks).toString()));
    return;
  }
  if (req.method === 'DELETE') { send(res, 'deleted'); return; }
  // Echo a custom request header back so httpRequest header passing can be tested.
  if (req.headers['x-echo']) { send(res, 'echo:' + req.headers['x-echo']); return; }
  send(res, BODY);
});

srv.listen(0, '127.0.0.1', () => {
  process.stdout.write(`PORT ${srv.address().port}\n`);
});
