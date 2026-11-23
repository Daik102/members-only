import { Router } from 'express';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { body, validationResult } from 'express-validator';
import { pool } from '../config/db.js';
import { ensureGuest } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 10;

// Validation rules middleware array
const signupValidation = [
  body('first_name')
    .trim()
    .notEmpty()
    .withMessage('First name is required.')
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters.'),

  body('last_name')
    .trim()
    .notEmpty()
    .withMessage('Last name is required.')
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters.'),

  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required.')
    .isLength({  max: 50 })
    .withMessage('Username cannot exceed 50 characters.')
    // Custom async validator to check if username already exists in Postgres!
    .custom(async (value) => {
      const { rows } = await pool.query('SELECT id FROM users WHERE username = $1', [value]);
      if (rows.length > 0) {
        throw new Error('That username is already taken.');
      }
      return true;
    }),

  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long.'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    }),
];

const loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required.'),

  body('password')
    .notEmpty()
    .withMessage('Password is required.')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long.'),
];

// --- SIGN UP ---
router.get('/signup', ensureGuest, (req, res) => {
  res.render('signup', { errors: [], oldInput: {} });
});

router.post('/signup', ensureGuest, signupValidation, async (req, res, next) => {
  const { first_name, last_name, username, password } = req.body;

  // 1. Check validation results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Re-render form with error messages and preserved user inputs (never send passwords back!)
    return res.status(400).render('signup', {
      errors: errors.array(),
      oldInput: { first_name, last_name, username },
    });
  }

  try {
    // 2. Hash password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // 3. Insert user into Postgres (confirmPassword is NOT saved to the database)
    const { rows } = await pool.query(
      `INSERT INTO users (first_name, last_name, username, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, is_member, is_admin`,
      [first_name, last_name, username, passwordHash]
    );
    const newUser = rows[0];

    // 4. Automatically log in the new user and save session before redirecting
    req.login(newUser, (err) => {
      if (err) return next(err);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect('/');
      });
    });
  } catch (err) {
    next(err);
  }
});

// --- LOG IN ---
router.get('/login', ensureGuest, (req, res) => {
  res.render('login', { errors: [], oldInput: {} });
});

router.post('/login', ensureGuest, loginValidation, (req, res, next) => {
  const { username } = req.body;

  // 1. Check express-validator errors first (before calling Passport/DB)
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', {
      errors: errors.array(),
      oldInput: { username },
    });
  }

  // 2. Run Passport authentication
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      // Re-render with Passport's failure message in the same `errors` format
      return res.status(401).render('login', {
        errors: [{ msg: info?.message || 'Invalid credentials.' }],
        oldInput: { username },
      });
    }

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect('/');
      });
    });
  })(req, res, next);
});

// --- LOG OUT ---
router.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });
});

export default router;
