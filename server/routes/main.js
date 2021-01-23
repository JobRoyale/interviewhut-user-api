const express = require('express');

const mainRouter = express.Router();

mainRouter.get('/', (req, res) => {
  res.send('InterviewHut user API is up and running');
});

module.exports = mainRouter;
