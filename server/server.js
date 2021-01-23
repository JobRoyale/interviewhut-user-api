if (process.env.NODE_ENV !== 'production') require('dotenv').config();
const express = require('express');
const os = require('os');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const mainRouter = require('./routes/main');
const usersRouter = require('./routes/users');

const PORT = process.env.SERVER_PORT || 5000;

(async () => {
  try {
    await mongoose.connect(process.env.TEST_DATABASE, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to DB');
  } catch (error) {
    console.log('DB connection failed', error);
  }
})();

const app = express();
app.use(express.json());

app.use(cookieParser());

app.use('/', mainRouter);
app.use('/users', usersRouter);

const server = app.listen(PORT, () => {
  const host = os.hostname();
  console.log('Server started at ', host, ':', server.address().port);
});
