let internalOAuthError = Object.create(Error, {
  build: {
    writable: true,
    configurable: true,
    enumerable: true,
    value: function(message, err) {
      Error.captureStackTrace(this, this.constructor);
      this.message = message;
      this.oauthError = err;
    }
  },
  toString: {
    writable: true,
    configurable: true,
    enumerable: true,
    value: function() {
      var m = this.name;
      if (this.message) { m += ': ' + this.message; }
      if (this.oauthError) {
        if (this.oauthError instanceof Error) {
          m = this.oauthError.toString();
        } else if (this.oauthError.statusCode && this.oauthError.data) {
          m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
        }
      }
      return m;
    }
  }
});

export { internalOAuthError };