import { Router } from 'express';
import { pool } from '../config/db.js';
import { ensureAuthenticated } from '../middleware/auth.js';

const router = Router();

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

// Create post (Authenticated users only)
router.post('/posts', ensureAuthenticated, async (req, res, next) => {
  try {
    const { title, content } = req.body;
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
      return res.status(404).send('Post not found');
    }

    // THE AUTHORIZATION CHECK:
    const isOwner = post.user_id === req.user.id;
    const isAdmin = req.user.is_admin;

    if (!isOwner && !isAdmin) {
      return res.status(403).send('Forbidden: You do not own this post.');
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [postId]);
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

export default router;
