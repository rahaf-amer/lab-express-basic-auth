const express = require("express");
const router = express.Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");

// require auth middleware
const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard.js");

router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  console.log("The form data: ", req.body);
  const { username, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        username,
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDb) => {
      res.redirect("/userProfile");
      // console.log('Newly created user is: ', userFromDb);
    })
    .catch((error) => next(error));
});

router.get("/userProfile", isLoggedIn, (req, res) => {
  res.render("users/user-profile", { userInSession: req.session.currentUser });
});

// GET route ==> to display the login form to users
router.get("/login", (req, res) => res.render("auth/login"));

router.post("/login", (req, res, next) => {
  console.log("SESSION =====> ", req.session);
  const { username, password } = req.body;

  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "Email is not registered. Try with other email.",
        });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        req.session.currentUser = user;
        res.redirect("/userProfile");
      } else {
        res.render("auth/login", { errorMessage: "Incorrect password." });
      }
    })
    .catch((error) => {
      next(error);
    });
});

router.get("/userProfile", (req, res) => {
  res.render("users/user-profile", { userInSession: req.session.currentUser });
});

router.post("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) next(err);
    res.redirect("/");
  });
});

router.get("/main", isLoggedIn, (req, res) => {
  res.render("main", { userInSession: req.session.currentUser });
});
router.get("/private", isLoggedIn, (req, res) => {
  res.render("private", { userInSession: req.session.currentUser });
});

module.exports = router;
