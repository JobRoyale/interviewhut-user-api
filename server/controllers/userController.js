const bcrypt = require('bcrypt');
const User = require('../models/user');
const {
  getRefreshToken,
  getCookieOptions,
  getUserNameToken,
  getAccessToken,
  verifyToken,
} = require('../utils/auth');
const googleAuth = require('../utils/googleAuth');
const SERVER_RESPONSE = require('../utils/serverResponses');

// Destructing array containing secrets for refresh and access token
const [ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET] = [
  process.env.ACCESS_TOKEN_SECRET,
  process.env.REFRESH_TOKEN_SECRET,
];

const signUpUser = (req, res) => {
  try {
    if (req.body.issuer === 'google') {
      googleAuth(req.body.accessToken)
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
                  password: hashPassword,
                  issuer: req.body.issuer,
                  signUpType: req.body.signUpType,
                  profilePic: data.picture,
                });

                newUser
                  .save()
                  .then(() => {
                    res.status(201).json({
                      status: true,
                      payload: {
                        message: SERVER_RESPONSE.CREATED,
                      },
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
        .catch((error) => {
          console.log(error);
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

const loginUser = (req, res) => {
  try {
    if (req.body.issuer === 'google') {
      googleAuth(req.body.accessToken)
        .then((data) => {
          User.find({ email: data.email })
            .exec()
            .then((user) => {
              if (user.length >= 1) {
                res.cookie(
                  'interviewhut_rtk',
                  getRefreshToken(user[0]),
                  getCookieOptions(604800000)
                );
                res.cookie(
                  'interviewhut_u',
                  getUserNameToken(user[0]),
                  getCookieOptions(604800000)
                );
                res.status(200).json({
                  status: true,
                  payload: {
                    message: SERVER_RESPONSE.LOGIN,
                    accessToken: getAccessToken(user[0]),
                  },
                });
              } else {
                res.status(403).json({
                  status: false,
                  payload: {
                    message: SERVER_RESPONSE.REGISTER,
                  },
                });
              }
            })
            .catch((error) => {
              console.log(error);
              res.status(500).json({
                status: false,
                payload: { message: SERVER_RESPONSE.ERROR },
              });
            });
        })
        .catch((error) => {
          res.status(401).json({
            status: false,
            payload: {
              message: SERVER_RESPONSE.ERRORTOKEN,
            },
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
      payload: { message: SERVER_RESPONSE.ERROR },
    });
  }
};

const preCheckUser = async (req, res) => {
  try {
    // Extracting accessToken from headers passed by client
    let accessToken = req.headers.authorization.split(' ')[1];
    // Extracting userNameToken, refreshToken from cookies
    const refreshToken = req.cookies.interviewhut_rtk;
    const userNameToken = req.cookies.interviewhut_u;

    let payload;

    if (!userNameToken) {
      res.status(403).json({
        status: false,
        payload: {
          message: SERVER_RESPONSE.LOGINREQUIRED,
        },
      });
    }

    let username;

    // Extracting username from userNameToken
    try {
      username = verifyToken(userNameToken, ACCESS_TOKEN_SECRET).username;
    } catch (error) {
      console.log(error);
      throw new Error('Token Not Provided');
    }

    // Verifying accessToken
    try {
      payload = verifyToken(accessToken, ACCESS_TOKEN_SECRET + username);
    } catch (error) {
      if (error.message !== 'jwt expired') {
        throw new Error('Token Man Handled');
      }
    }

    // If accessToken verification failed, thats means server has to renew accessToken
    if (!payload) {
      // Getting userData from db
      const user = await User.findOne({ username });

      // Verifying refreshToken
      payload = verifyToken(refreshToken, REFRESH_TOKEN_SECRET + user.password);

      // Both accessToken and refreshToken are invalid
      if (!payload) {
        throw new Error('Auth Failed');
      }

      // Renewing tokens
      accessToken = getAccessToken(user);
      res.cookie(
        'interviewhut_rtk',
        getRefreshToken(user),
        getCookieOptions(604800000)
      );
      res.cookie(
        'interviewhut_u',
        getUserNameToken(user),
        getCookieOptions(604800000)
      );
    }

    res.status(200).json({
      status: true,
      payload: {
        message: SERVER_RESPONSE.TOKEN,
        accessToken: accessToken,
      },
    });
  } catch (error) {
    console.log(error);
    res.clearCookie('grupo_rtk');
    res.clearCookie('grupo_u');
    res.status(401).json({
      status: false,
      payload: {
        message: SERVER_RESPONSE.AUTHERROR,
      },
    });
  }
};

const logoutUser = (req, res) => {
  try {
    res.clearCookie('interviewhut_rtk');
    res.clearCookie('interviewhut_u');
    res.status(200).json({
      status: true,
      payload: {
        message: SERVER_RESPONSE.LOGOUT,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: false,
      payload: {
        message: SERVER_RESPONSE.ERROR,
      },
    });
  }
};

module.exports = { signUpUser, loginUser, preCheckUser, logoutUser };
