import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';

import { pool } from './config/db.js';
import passport from './config/passport.js';
import indexRouter from './routes/indexRouter.js';
import authRouter from './routes/authRouter.js';

const app = express();
const PORT = process.env.PORT || 3000;
const PgSession = connectPgSimple(session);

// Required for Render's reverse proxy so secure cookies work
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session setup backed by Neon/Postgres
app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      httpOnly: true, // Prevents client-side JS (XSS) from reading the cookie
      secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
      sameSite: 'lax', // Protects against basic CSRF
    },
  })
);

app.use(passport.session());

// Global template variables
app.use((req, res, next) => {
  res.locals.currentUser = req.user || null;
  res.locals.error = req.session.error || null;
  delete req.session.error; // Clear message after reading once
  next();
});

app.use('/', indexRouter);
app.use('/', authRouter);

app.use((req, res, next) => {
  const err = new Error('Page Not Found');
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  const statusCode = err.status || 500;
  
  res.status(statusCode).render('error', { 
    title: `Error ${statusCode}`, 
    message:
      process.env.NODE_ENV === 'production'
        ? 'Something went wrong on our end.'
        : err.message,
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Express server running at http://localhost:${PORT}`);
});
