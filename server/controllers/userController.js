const bcrypt = require('bcrypt');
const User = require('../models/user');
const {
  getRefreshToken,
  getCookieOptions,
  getUserNameToken,
  getAccessToken,
} = require('../utils/auth');
const googleAuth = require('../utils/googleAuth');
const SERVER_RESPONSE = require('../utils/serverResponses');

const signUpUser = (req, res) => {
  try {
    if (req.body.issuer === 'google') {
      googleAuth(req.body.accesToken)
        .then((data) => {
          User.find({ email: data.email })
            .exec()
            .then((user) => {
              if (user.length === 1) {
                return res.status(409).json({
                  status: false,
                  payload: { message: SERVER_RESPONSE.CONFLICT },
                });
              }
              let username = data.email.match(/^([^@]*)@/)[1];
              User.find({ username })
                .exec()
                .then((userCheck) => {
                  if (userCheck.length !== 0) {
                    username += userCheck.length;
                  }
                })
                .catch((error) => {
                  console.log(error);
                  res.status(500).json({
                    status: false,
                    payload: { message: SERVER_RESPONSE.ERROR },
                  });
                });
              bcrypt.hash(req.body.password, 10, (error, hashPassword) => {
                if (error) {
                  console.log(error);
                  throw new Error('Password encryption failed');
                }

                const newUser = new User({
                  username: username,
                  firstname: data.given_name,
                  lastname: data.family_name,
                  email: data.email,
                  password: hashedPassword,
                  issuer: req.body.issuer,
                  signUpType: req.body.signUpType,
                  profilePic: data.picture,
                });

                newUser
                  .save()
                  .then(() => {
                    res.status(201).json({
                      status: true,
                      payload: SERVER_RESPONSE.CREATED,
                    });
                  })
                  .catch((error) => {
                    console.log(error);
                    res.status(406).json({
                      status: false,
                      payload: { message: SERVER_RESPONSE.MISSING },
                    });
                  });
              });
            })
            .catch((error) => {
              console.log(error);
              res.status(500).json({
                status: false,
                payload: {
                  message: SERVER_RESPONSE.ERROR,
                },
              });
            });
        })
        .catch(() => {
          res.status(401).json({
            status: false,
            payload: { message: SERVER_RESPONSE.ERRORTOKEN },
          });
        });
    } else {
      res.status(500).json({
        status: false,
        payload: { message: SERVER_RESPONSE.ERROR },
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: false,
      payload: {
        message: SERVER_RESPONSE.ERROR,
      },
    });
  }
};

const loginUser = (req, res) => {};

const logoutUser = (req, res) => {};

module.exports = { signUpUser, loginUser, logoutUser };
