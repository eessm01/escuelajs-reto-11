const passport = require('passport');
const { BasicStrategy } = require('passport-http');
const bcrypt = require('bcrypt');

const UsersService = require('../../../services/users');

passport.use(
  new BasicStrategy(async (email, password, cb) => {
    const userService = new UsersService();

    // user exist?
    try {
      const user = await userService.getUser({ email })
      if(!user) {
        return cb(new Error('Unauthorized user'), false);
      }

      // compare ingressed password with password in database
      if(!(await bcrypt.compare(password,user.password))) {
        return cb('unauthorized user', false);
      }

      delete user.password;

      return cb(null, user);

    } catch(error) {
      cb(error);
    }
  })
)