const dotenv = require('dotenv');
dotenv.config();
module.exports = {
  "jwtConfig": {
    "jwtSecret": process.env.JWT_SECRET,
    "jwtLifeTime": process.env.JWT_LIFE_TIME
  },
};