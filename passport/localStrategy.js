const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');

passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password'
},
  async (username, password, done) => {
    let foundUser;
    try {
      foundUser = await User.findOne({ username });
      if (!foundUser) {
        done(null, false, { message: 'Incorrect username' });
        return;
      }
    } catch (e) {
      return done(e);
    }
    const match = await bcrypt.compare(password, foundUser.password);
    if (!match) {
      done(null, false, { message: 'Incorrect password' });
      return;
    }
    return done(null, foundUser);
  }
));