import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { pool } from '../config/db.js';
import { ensureAuthenticated } from '../middleware/auth.js';

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

export default router;
