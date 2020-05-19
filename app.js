const express = require(`express`);
const bodyparser = require(`body-parser`);
const mongoose = require(`mongoose`);
const bcrypt = require(`bcryptjs`);
const flash = require(`connect-flash`);
const session = require(`express-session`);
const passport = require(`passport`);
const Localstrategy = require(`passport-local`).Strategy;
const {ensureAuthenticated} = require(`./config`)

const app = express();

//body-parser middleware
app.use(bodyparser.urlencoded({extended: false}));
app.use(bodyparser.json());

//set static file
app.use(express.static(`public`));

//set view engine
app.set(`view engine`, `ejs`);

//express-session middleware
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true,
}));

//passport middleware
app.use(passport.initialize());
app.use(passport.session());

// connect-flash middleware
app.use(flash());

//Global vars
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash(`success_msg`);
  res.locals.error_msg = req.flash(`error_msg`);
  res.locals.error = req.flash(`error`);
  next();
})


//database connection and schema setup
mongoose.connect(`mongodb://localhost:27017/usersDB`, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  password2: {
    type: String,
  } 
});

const User = mongoose.model(`User`, userSchema);


//Routes
app.get(`/`, function(req, res) {
  res.render(`home`);
})

app.get(`/register`, function(req, res) {
  res.render(`register`);
})

app.get(`/login`, function(req, res) {
  res.render(`login`);
})

app.get(`/dashboard`, ensureAuthenticated, function(req, res) {
  res.render(`dashboard`, {
    name: req.user.name
  });
})
//handle post
app.post(`/register`, function(req, res) {
  const {name, email, password, password2} = req.body;
  //Validation - check errrors
  const errors = [];
  
  if(!name || !email || !password || !password2) {
    errors.push({msg: `All fields are required.`});
  }

  if(password != password2) {
    errors.push({msg: `Passwords do not match.`});
  }

  if(password.length < 6) {
    errors.push({msg: `Password must be at least 6 characters.`});
  }

  if(errors.length > 0) {
    res.render(`register`, {
      errors, name, email, password, password2
    })
  } else {
    User.findOne({email: email})
      .then(user => {
        //match user
        if(user) {
          errors.push({msg: `Email is already registered.`});
          res.render(`register`, {
            errors, name, email, password, password2
          })
        } else {
          //create new user
          const newUser = new User({
            name, email, password
          })

          //Encrypt user password
          bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(newUser.password, salt, function(err, hash) {
              newUser.password = hash;

              newUser.save(function(err, saved) {
                if(err) {
                  console.log(err)
                } else {
                  req.flash(`success_msg`, `You're now registered and can now log in.`)
                  res.redirect(`/login`);
                }
              })
            })
          })
        }
      })
  }
});

//Using passport-local to authenticate

passport.use(
  new Localstrategy({usernameField: `email`}, (email, password, done) => {
    //Match user
    User.findOne({email: email})
      .then(user => {
        if(!user) {
          return done(null, false, {message: `Email is not registered`})
        }
        //Match password with hashes in DB
        bcrypt.compare(password, user.password, function(err, isMatch) {
          if(err) throw err;
          if(isMatch) {
            return done(null, user)
          } else {
            return done(null, false, {message: `Incorrect Password`})
          }
        })
      })
  })
);
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//login post handle
app.post(`/login`, function(req, res, next) {
  passport.authenticate(`local`, {
    successRedirect: `/dashboard`,
    failureRedirect: `/login`,
    failureFlash: true,

  })(req, res, next);
})
//logout handle
app.get(`/logout`, function(req, res) {
  req.logout();
  req.flash(`success_msg`, `Successfully logged out`);
  res.redirect(`/`);
})

//Listening port
app.listen(4000, function() {
  console.log(`Server is running on port 4000`);
})