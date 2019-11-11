const passport = require('passport');
const { Strategy, ExtractJwt } = require('passport-jwt');

const UsersService = require('../../../services/users');

const { config } = require('../../../config/index');

passport.use(
  new Strategy(
    {
      secretOrKey: config.authJwtSecret,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
    },
    async function (tokenPayload, cb) {
      const userService = new UsersService();

      try {
        // search user in database with email
        const user = await userService.getUser({ email: tokenPayload.email });

        if(!user) {
          return cb(new Error('Unauthorized user'), false);
        }

        delete user.password;

        // return user information and scopes
        cb(null, {...user, scopes: tokenPayload.scopes });

      } catch(error) {
        cb(error);
      }
    }
  )
);
