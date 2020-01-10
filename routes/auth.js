const express = require("express");
const passport = require("passport");
const router = express.Router();
const User = require("../models/User");

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

router.get("/login", (req, res, next) => {
  res.render("auth/login", { message: req.flash("error") });
});

router.post("/login", (req, res) => {
  passport.authenticate("local", (err, user) => {
    if (err) {
      return res.status(500).json({ message: "Error while authenticating" });
    }
    if (!user) {
      return res.status(400).json({ message: "Wrong credentials" });
    }
    req.login(user, err => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error while attempting to login" });
      }
      return res.json(user);
    });
  })(req, res);
});

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === "") {
    return res.status(400).json({ message: "Your email cannot be empty" });
  }
  if (!password || password.length < 8) {
    return res
      .status(400)
      .json({ message: "Your password must be at least 8 characters" });
  }

  User.findOne({ username }, "username", async (err, user) => {
    if (user !== null) {
      return res
        .status(400)
        .json({ message: "An account for this email already exists" });
    }

    const salt = await bcrypt.genSalt(bcryptSalt);
    const hashPass = await bcrypt.hash(password, salt);

    return User.create({ username: username, password: hashPass }).then(
      dbUser => {
        // Login the user on signup
        req.login(dbUser, err => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Error while attempting to login" });
          }
          res.json(dbUser);
        });
      }
    );
  }).catch(err => {
    res.json(err);
  });
});

router.delete("/logout", (req, res) => {
  req.logout();
  res.json({ message: "Logout successful" });
});

// checks if the user has an active session
// GET /auth/loggedin
router.get("/loggedin", (req, res) => {
  res.json(req.user);
});

module.exports = router;