const express = require("express");
const mongoose = require("mongoose");
const flash = require("connect-flash");
const session = require("express-session");
const expressLayouts = require("express-ejs-layouts");
const indexRouter = require("./routes/index");
const userRouter = require("./routes/users");
const passport = require("passport");
const app = express();

//Passsport config
require("./config/passport")(passport);

//DB config;

const db = require("./config/keys").MongoURI;

//Connect to Mongo
mongoose
  .connect(db, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("MongoDB Connected");
  })
  .catch((err) => {
    console.log(err);
  });

//MiddleWare

//BodyParser
app.use(express.urlencoded({ extended: true }));

//Express-Session
app.use(
  session({
    secret: "sanket",
    resave: true,
    saveUninitialized: true,
  })
);

//Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

//Connect Flash
app.use(flash());

//Global VARS

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});

//EJS
app.use(expressLayouts);
app.set("view engine", "ejs");

app.use("/", indexRouter);
app.use("/users", userRouter);
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server Started on Port ${PORT}`);
});
