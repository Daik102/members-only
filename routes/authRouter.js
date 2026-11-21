import { Router } from 'express';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { pool } from '../config/db.js';
import { ensureGuest } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 10;

// --- SIGN UP ---
router.get('/signup', ensureGuest, (req, res) => {
  res.render('signup');
});

router.post('/signup', ensureGuest, async (req, res, next) => {
  const { username, password } = req.body;

  try {
    // 1. Basic validation
    if (!username || !password || password.length < 6) {
      req.session.error = 'Username is required and password must be at least 6 characters.';
      return res.redirect('/signup');
    }

    // 2. Hash password before touching the database
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // 3. Insert user and return the newly created record
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, is_admin',
      [username.trim(), passwordHash]
    );

    const newUser = rows[0];

    // 4. Automatically log the user in after registration
    req.login(newUser, (err) => {
      if (err) {
        return next(err);
      }

      res.redirect('/');
    });
  } catch (err) {
    // Postgres error code 23505 = unique_violation (username already taken)
    if (err.code === '23505') {
      req.session.error = 'That username is already taken.';

      // Wait for Postgres to save the session BEFORE redirecting
      return req.session.save((saveErr) => {
        if (saveErr) {
          return next(saveErr)
        };

        res.redirect('/signup');
      });
    }

    next(err);
  }
});

// --- LOG IN ---
router.get('/login', ensureGuest, (req, res) => {
  res.render('login');
});

router.post('/login', ensureGuest, (req, res, next) => {
  // Custom callback allows us to pass Passport's failure messages into req.session.error
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      req.session.error = info?.message || 'Invalid credentials.';
      // Wait for Postgres to save the session BEFORE redirecting
      return req.session.save((saveErr) => {
        if (saveErr) {
          return next(saveErr);
        };

        res.redirect('/login');
      });
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        return next(loginErr)
      };

      req.session.save((saveErr) => {
        if (saveErr) {
          return next(saveErr)
        };

        res.redirect('/');
      });
    });
  })(req, res, next);
});

// --- LOG OUT ---
// Always use POST for logout to prevent accidental/malicious logouts via links or prefetching
router.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }

    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });
});

export default router;
