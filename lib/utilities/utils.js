export function merge(a, b) {
  if (a && b) {
    for (let key in b) {
      a[key] = b[key];
    }
  }
  return a;
}

export function originalURL(req, options) {
  options = options || {};
  let app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  let trustProxy = options.proxy;
  
  let proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  let tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0]);
  let host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
  let protocol = tls ? 'https' : 'http';
  let path = req.url || '';
  return protocol + '://' + host + path;
}

export function catchAsyncErrors(req, res, next) {
  const routePromise = fn(req, res, next);
  if (routePromise.catch) {
    routePromise.catch(err => next(err));
  }
}

export function btoa(str) {
  var buffer;

  if (str instanceof Buffer) {
    buffer = str;
  } else {
    buffer = Buffer.from(str.toString(), 'binary');
  }

  return buffer.toString('base64');
}
