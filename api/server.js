const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const userRouter = require('../users/users-router');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use('/api', userRouter);


server.get('/', (req, res) => {
  res.send("So.. You've made it inside.");
});

module.exports = server;
