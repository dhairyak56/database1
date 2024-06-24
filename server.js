const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const flash = require('connect-flash');
const mysql = require('mysql2');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Initialize Express App
const app = express();

// MySQL connection pool setup
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.on('error', err => {
    console.error('db error', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.fatal) {
        handleDisconnect();
    } else {
        throw err;
    }
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Set EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Passport Config for Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' },
    (email, password, done) => {
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) return done(err);
            if (!results.length) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            const user = results[0];
            if (!bcrypt.compareSync(password, user.password)) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user);
        });
    }
));

// Passport Config for Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
}, (token, tokenSecret, profile, done) => {
    db.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
        if (err) return done(err);
        if (results.length) {
            return done(null, results[0]);
        } else {
            const newUser = {
                google_id: profile.id,
                email: profile.emails[0].value,
                name: profile.displayName,
                role: 'user'
            };
            db.query('INSERT INTO users SET ?', newUser, (err, res) => {
                if (err) return done(err);
                newUser.id = res.insertId;
                return done(null, newUser);
            });
        }
    });
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// Middleware for Role-Based Access Control
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    }
    res.redirect('/login');
}

function ensureManager(req, res, next) {
    if (req.isAuthenticated() && (req.user.role === 'admin' || req.user.role === 'manager')) {
        return next();
    }
    res.redirect('/login');
}

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'views', 'signup.html')));
app.get('/dashboard', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.get('/notification', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'notification.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'views', 'about.html')));
app.get('/events', (req, res) => {
    db.query('SELECT * FROM events', (err, results) => {
        if (err) {
            console.error('Database Error:', err);
            req.flash('error', 'There was an error retrieving the events.');
            return res.redirect('/');
        }
        res.render('events', { events: results, user: req.user });
    });
});
app.get('/post_event', ensureAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'views', 'post_event.html')));
app.get('/faqs', (req, res) => res.sendFile(path.join(__dirname, 'views', 'faqs.html')));

// Google OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // Successful authentication, redirect to dashboard.
        res.redirect('/dashboard');
    }
);

app.post('/login', [
    body('email').isEmail().withMessage('Enter a valid email').normalizeEmail(),
    body('password').notEmpty().withMessage('Password cannot be empty'),
], (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(err => err.msg).join(' '));
        return res.redirect('/login');
    }

    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
});

app.post('/signup', [
    body('email').isEmail().withMessage('Enter a valid email').normalizeEmail(),
    body('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters long'),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(err => err.msg).join(' '));
        return res.redirect('/signup');
    }

    const { email, password, role } = req.body; // Assuming role can be selected during signup
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.redirect('/signup');
        }
        if (results.length) {
            req.flash('error', 'Email is already registered');
            return res.redirect('/signup');
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        db.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashedPassword, role], (err, results) => {
            if (err) {
                console.error(err);
                return res.redirect('/signup');
            }
            req.flash('success', 'You are now registered and can log in');
            res.redirect('/login');
        });
    });
});

app.post('/events', ensureAuthenticated, [
    body('name').notEmpty().withMessage('Event name is required'),
    body('organization').notEmpty().withMessage('Organization name is required'),
    body('location').notEmpty().withMessage('Location is required'),
    body('time').notEmpty().withMessage('Time is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('date').isISO8601().withMessage('Date must be a valid date'),
    body('image').isURL().withMessage('Image must be a valid URL')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(err => err.msg).join(' '));
        return res.redirect('/post_event');
    }

    const { name, organization, location, time, description, date, image } = req.body;
    console.log('Event Data:', req.body); // Log the event data

    db.query('INSERT INTO events (name, organization, location, time, description, date, image, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
    [name, organization, location, time, description, date, image, req.user.id], (err, results) => {
        if (err) {
            console.error('Database Error:', err);
            req.flash('error', 'There was an error posting the event.');
            return res.redirect('/post_event');
        }
        console.log('Event Posted:', results);
        req.flash('success', 'Event posted successfully!');
        res.redirect('/events');
    });
});

app.post('/rsvp', ensureAuthenticated, [
    body('eventId').notEmpty().withMessage('Event ID is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(err => err.msg).join(' '));
        return res.redirect('/events');
    }

    const { eventId } = req.body;

    // Save RSVP to database
    db.query('INSERT INTO rsvps (user_id, event_id) VALUES (?, ?)', [req.user.id, eventId], (err, results) => {
        if (err) {
            console.error('Database Error:', err);
            req.flash('error', 'There was an error processing your RSVP.');
            return res.redirect('/events');
        }

        // Fetch event details for email
        db.query('SELECT * FROM events WHERE id = ?', [eventId], (err, eventResults) => {
            if (err) {
                console.error('Database Error:', err);
                req.flash('error', 'There was an error processing your RSVP.');
                return res.redirect('/events');
            }

            const event = eventResults[0];

            // Send confirmation email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: req.user.email,
                subject: 'RSVP Confirmation',
                text: `You have successfully RSVP'd to ${event.name} happening at ${event.location} on ${event.date} at ${event.time}.`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Email Error:', error);
                    req.flash('error', 'There was an error sending your RSVP confirmation.');
                    return res.redirect('/events');
                }

                req.flash('success', 'RSVP successful! A confirmation email has been sent.');
                res.redirect('/events');
            });
        });
    });
});

app.get('/profile', ensureAuthenticated, (req, res) => {
    res.render('profile', { user: req.user });
});

app.post('/profile', ensureAuthenticated, [
    body('email').isEmail().withMessage('Enter a valid email').normalizeEmail(),
    body('name').notEmpty().withMessage('Name cannot be empty'),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(err => err.msg).join(' '));
        return res.redirect('/profile');
    }

    const { email, name } = req.body;
    db.query('UPDATE users SET email = ?, name = ? WHERE id = ?', [email, name, req.user.id], (err, results) => {
        if (err) {
            console.error('Database Error:', err);
            req.flash('error', 'There was an error updating your profile.');
            return res.redirect('/profile');
        }
        req.flash('success', 'Profile updated successfully!');
        res.redirect('/profile');
    });
});

app.get('/admin', ensureAdmin, (req, res) => {
  db.query('SELECT * FROM users', (err, users) => {
      if (err) {
          console.error('Database Error:', err);
          req.flash('error', 'There was an error retrieving the users.');
          return res.redirect('/dashboard');
      }
      res.render('admin', { users: users, user: req.user, messages: req.flash() });
  });
});


app.get('/manage', ensureManager, (req, res) => {
    db.query('SELECT * FROM events WHERE user_id = ?', [req.user.id], (err, events) => {
        if (err) {
            console.error('Database Error:', err);
            req.flash('error', 'There was an error retrieving the events.');
            return res.redirect('/dashboard');
        }
        res.render('manage', { events: events, user: req.user });
    });
});

// Logout Route
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout Error:', err);
            return res.redirect('/dashboard'); // Redirect to dashboard if there is an error
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Session Destroy Error:', err);
                return res.redirect('/dashboard');
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            req.flash('success', 'You have logged out successfully.');
            res.redirect('/'); // Redirect to home page after logout
        });
    });
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});

app.use(express.static(path.join(__dirname, 'public')));
