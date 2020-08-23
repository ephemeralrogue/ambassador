let authenticationError = Object.create(Error, {
  build: {
    value: function(message, status) {
      Error.captureStackTrace(this, this.constructor);
      this.name = 'AuthenticationError';
      this.message = message;
      this.status = status || 401;
    }
  }
});

export default authenticationError;