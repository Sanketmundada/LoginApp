const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();
const User = require("../models/User");
const passport = require("passport");

//Login Page

router.get("/login", (req, res) => {
  res.render("login");
});

//Register Page

router.get("/register", (req, res) => {
  res.render("register");
});

//Register Handle

router.post("/register", (req, res) => {
  const { name, email, password, password2 } = req.body;

  let errors = [];

  //Check Required Fields

  if (!name || !email || !password || !password2) {
    errors.push({ msg: "Please Fill all the Fields..." });
  }

  //Check if password match
  if (password2 !== password) {
    errors.push({ msg: "Password do not match ..." });
  }

  //Check pass length
  if (password.length < 6) {
    errors.push({ msg: "Password should be atleast 6 Characters..." });
  }

  if (errors.length > 0) {
    res.render("register", {
      errors,
      name,
      email,
      password,
      password2,
    });
  } else {
    //Validation pass

    User.findOne({ email: email }).then((user) => {
      if (user) {
        //User Exists
        errors.push({ msg: "User Already Exists !!!" });
        res.render("register", {
          errors,
          name,
          email,
          password,
          password2,
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
        });

        //Hash password
        bcrypt.genSalt(10, (err, salt) =>
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) {
              throw err;
            } else {
              //Set password to hash
              newUser.password = hash;

              //Save user
              newUser.save().then((user) => {
                req.flash(
                  "success_msg",
                  "You are now Registered and can Login ..."
                );
                res.redirect("/users/login");
              });
            }
          })
        );
      }
    });
  }
});

//Login Handle

router.post("/login", (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })(req, res, next);
});

//logout Handle

router.get("/logout", (req, res) => {
  req.logout();
  req.flash("success_msg", "You are logged out");
  res.redirect("/users/login");
});

module.exports = router;
