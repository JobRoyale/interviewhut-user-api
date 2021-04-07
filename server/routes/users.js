const express = require('express');
const { auth } = require('google-auth-library');
const {
  signUpUser,
  loginUser,
  preCheckUser,
  logoutUser,
} = require('../controllers/userController');
const authRequest = require('../middlewares/authRequest');

const usersRouter = express.Router();

usersRouter.post('/signup', signUpUser);
usersRouter.post('/login', loginUser);
usersRouter.get('/precheck', preCheckUser);
usersRouter.get('/logout', logoutUser);

module.exports = usersRouter;
