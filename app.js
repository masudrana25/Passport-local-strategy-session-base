const express = require('express');
const cors = require('cors');
const ejs = require('ejs');
const app = express();
require('./config/database');
const User = require('./models/user.schema.model');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');
require('./config/passport');

app.use(cors());
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// session 
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: 'mongodb://127.0.0.1:27017/passportTestDB',
    collectionName: "sessions",
  })
  // cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());

//home url
app.get('/', (req, res) => {
  res.render('index');
});

//register get
app.get('/register', (req, res) => {
  res.render('register');
});

//register post
app.post('/register', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (user) return res.status(400).send('User is already exist');

    bcrypt.hash(req.body.password, saltRounds, async function (err, hash) {
      const newUser = new User({
      username: req.body.username,
      password: hash,
      });
      await newUser.save();
    // res.status(201).send(newUser);
      res.redirect('/login');
    });
  } catch (error) {
    res.status(500).send(error.message);
    process.exit(1);
  }
});


// login get
const checkLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect('/profile');
  };
  next();
}

app.get('/login',checkLoggedIn, (req, res) => {
  res.render('login');
});

//login post
app.post('/login',
  passport.authenticate('local', {
    failureRedirect: '/login',
    successRedirect: '/profile',
  })
);

//profile protected route
const checkAuthenticated = (req, res, next) =>{
  if (req.isAuthenticated()) {
    return next();
  };
  res.redirect('/login')
};

app.get('/profile', checkAuthenticated, (req, res) => {
  res.render("profile");
  // if (req.isAuthenticated) {
  //   res.render('profile');
  // }
  // res.redirect('/login');
});

//logout route
app.get('/logout', (req, res) => {
  try {
    req.logout((err)=>{
      if (err) {
      return next(err);
      };
      res.redirect('/');
    })
  } catch (error) {
    res.status(500).send(error.message);
  }
});






module.exports = app;
