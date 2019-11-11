const MongoLib = require('../lib/mongo');
const bcrypt = require('bcrypt');

class UsersService {
  constructor() {
    this.collection = 'users';
    this.MongoDB = new MongoLib();
  }

  // methods
  
  // search user through user-email
  async getUser({ email }){
    const [user] = await this.MongoDB.getAll(this.collection, { email });
    return user;
  };

  // create user with hashed password
  async createUser({ user }) {
    const { name, email, password } = user;
    // encrypted password
    const hashedPassword = await bcrypt.hash(password, 10);

    // insert user to DB
    const createUserId = this.MongoDB.create(this.collection, {
      name, 
      email, 
      password: hashedPassword
    });

    return createUserId;
  };
}

module.exports = UsersService;