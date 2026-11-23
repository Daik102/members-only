import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { pool } from '../config/db.js';
import { ensureAuthenticated, ensureAdmin } from '../middleware/auth.js';

const router = Router();

const postValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Post title is required.')
    .isLength({ max: 150 })
    .withMessage('Title cannot exceed 150 characters.'),

  body('content')
    .trim()
    .notEmpty()
    .withMessage('Post message cannot be empty.')
    .isLength({ max: 2000 })
    .withMessage('Post message cannot exceed 2000 characters.'),
];

const memberValidation = [
  body('passcode')
    .trim()
    .notEmpty()
    .withMessage('Please enter the secret passcode.')
    .custom((value) => {
      if (value !== process.env.CLUB_PASSCODE) {
        throw new Error('Incorrect secret passcode.');
      }
      return true;
    }),
];

const adminValidation = [
  body('passcode')
    .trim()
    .notEmpty()
    .withMessage('Please enter the admin passcode.')
    .custom((value) => {
      if (value !== process.env.ADMIN_PASSCODE) {
        throw new Error('Incorrect admin passcode.');
      }
      return true;
    }),
];

// Public feed
router.get('/', async (req, res, next) => {
  try {
    const { rows: posts } = await pool.query(`
      SELECT posts.*, users.username AS author
      FROM posts
      JOIN users ON posts.user_id = users.id
      ORDER BY posts.created_at DESC
    `);
    res.render('index', { posts });
  } catch (err) {
    next(err);
  }
});

// New post form page (Authenticated users only)
router.get('/posts/new', ensureAuthenticated, (req, res) => {
  res.render('new-post', { errors: [], oldInput: {} });
});

// Create post
router.post('/posts', ensureAuthenticated, postValidation, async (req, res, next) => {
  const { title, content } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('new-post', {
      errors: errors.array(),
      oldInput: { title, content },
    });
  }

  try {
    await pool.query(
      'INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3)',
      [title, content, req.user.id]
    );
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

// Delete post (Owner OR Admin only)
router.post('/posts/:id/delete', ensureAuthenticated, async (req, res, next) => {
  try {
    const postId = req.params.id;
    const { rows } = await pool.query('SELECT user_id FROM posts WHERE id = $1', [postId]);
    const post = rows[0];

    if (!post) {
      return res.status(404).render('error', {
        status: 404,
        title: 'Not Found',
        message: 'Post not found.',
      });
    }

    const isOwner = post.user_id === req.user.id;
    const isAdmin = req.user.is_admin;
    
    if (!isOwner && !isAdmin) {
      return res.status(403).render('error', {
        status: 403,
        title: 'Forbidden',
        message: 'You do not have permission to delete this post.',
      });
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [postId]);
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

router.get('/join', ensureAuthenticated, (req, res) => {
  if (req.user.is_member || req.user.is_admin) {
    return res.redirect('/');
  }
  res.render('join', { errors: [] });
});

router.post('/join', ensureAuthenticated, memberValidation, async (req, res, next) => {
  if (req.user.is_member || req.user.is_admin) {
    return res.redirect('/');
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('join', { errors: errors.array() });
  }

  try {
    await pool.query('UPDATE users SET is_member = TRUE WHERE id = $1', [req.user.id]);
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

router.get('/admin-join', ensureAuthenticated, (req, res) => {
  if (req.user.is_admin) {
    return res.redirect('/');
  }
  res.render('admin-join', { errors: [] });
});

router.post('/admin-join', ensureAuthenticated, adminValidation, async (req, res, next) => {
  if (req.user.is_admin) {
    return res.redirect('/');
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('admin-join', { errors: errors.array() });
  }

  try {
    await pool.query(
      'UPDATE users SET is_admin = TRUE, is_member = TRUE WHERE id = $1',
      [req.user.id]
    );
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

// --- ADMIN DASHBOARD ---
router.get('/admin', ensureAdmin, async (req, res, next) => {
  try {
    // Select safe columns only (never select password_hash)
    const { rows: users } = await pool.query(`
      SELECT id, first_name, last_name, username, is_member, is_admin, created_at
      FROM users
      ORDER BY id ASC
    `);
    res.render('admin', { users });
  } catch (err) {
    next(err);
  }
});

// Toggle Member status for a user
router.post('/admin/users/:id/toggle-member', ensureAdmin, async (req, res, next) => {
  try {
    const targetId = req.params.id;
    await pool.query(
      'UPDATE users SET is_member = NOT is_member WHERE id = $1',
      [targetId]
    );
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

// Toggle Admin status for another user
router.post('/admin/users/:id/toggle-admin', ensureAdmin, async (req, res, next) => {
  try {
    const targetId = Number(req.params.id);

    // Prevent an admin from accidentally removing their own admin status
    if (targetId === req.user.id) {
      return res.status(400).render('error', {
        status: 400,
        title: 'Bad Request',
        message: 'You cannot revoke your own admin privileges.',
      });
    }

    // Promoting to admin also grants member status; demoting keeps member status intact
    await pool.query(
      `UPDATE users
       SET is_admin = NOT is_admin,
           is_member = CASE WHEN NOT is_admin THEN TRUE ELSE is_member END
       WHERE id = $1`,
      [targetId]
    );
    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

export default router;
