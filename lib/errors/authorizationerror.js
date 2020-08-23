let authorizationError = Object.create(Error, {
  build: {
    writable: true,
    configurable: true,
    enumerable: true,
    value: function(message, code, uri, status) {
      if (!status) {
        switch (code) {
          case 'access_denied': status = 403; break;
          case 'server_error': status = 502; break;
          case 'temporarily_unavailable': status = 503; break;
        }
      }
      Error.captureStackTrace(this, this.constructor);
      this.name = this.constructor.name;
      this.message = message;
      this.code = code || 'server_error';
      this.uri = uri;
      this.status = status || 500;
    }
  }
});

export { authorizationError };
