module.exports = function () {
  const express = require('express');
  const app = express();
  const auth = require('./controllers/auth')();

  app.use('/auth', auth);

  return app;
}
