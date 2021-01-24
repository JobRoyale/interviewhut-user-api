const SERVER_RESPONSE = require('../utils/serverResponses');
const User = require('../models/user');
const {
  getAccessToken,
  getRefreshToken,
  getUserNameToken,
  verifyToken,
  getCookieOptions,
} = require('../utils/auth');

const [ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET] = [
  process.env.ACCESS_TOKEN_SECRET,
  process.env.REFRESH_TOKEN_SECRET,
];

const authRequest = async (req, res, next) => {
  try {
    let accessToken = req.headers.authorization.split(' ')[1];
    const refreshToken = req.cookies.interviewhut_rtk;
    let username = req.cookies.interviewhut_u;

    let payload;

    try {
      username = verifyToken(username, ACCESS_TOKEN_SECRET).username;
    } catch (error) {
      throw new Error('Token not provided');
    }

    try {
      payload = verifyToken(accessToken, ACCESS_TOKEN_SECRET + username);
    } catch (error) {
      if (error !== 'jwt expired') {
        res.clearCookie('interviewhut_rtk');
        res.clearCookie('interviewhut_u');
        throw new Error('Access token man Handled');
      }
    }

    if (!payload) {
      const user = await User.findOne({ username });

      payload = verifyToken(refreshToken, REFRESH_TOKEN_SECRET + user.password);

      if (!payload) {
        throw new Error('Auth Failed');
      }

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

      req.accessToken = accessToken;

      req.payload = payload;

      next();
    }
  } catch (error) {
    res.status(401).json({
      status: false,
      payload: { message: SERVER_RESPONSE.AUTHERROR },
    });
  }
};

module.exports = authRequest;
