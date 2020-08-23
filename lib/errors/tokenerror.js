let tokenError = Object.create(Error, {
  build: {
    writable: true,
    configurable: true,
    enumerable: true,
    value: function(message, code, uri, status) {
      captureStackTrace(this, this.constructor);
      this.name = this.constructor.name;
      this.message = message;
      this.code = code || 'invalid_request';
      this.uri = uri;
      this.status = status || 500;
    }
  }
});

export { tokenError };
