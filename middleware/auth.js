export function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  req.session.error = 'Please log in to view that page.';
  // Wait for Postgres to save the session BEFORE redirecting
  return req.session.save((err) => {
    if (err) {
      return next(err)
    };

    res.redirect('/login');
  });
}

export function ensureGuest(req, res, next) {
  if (!req.isAuthenticated()) {
    return next();
  }

  res.redirect('/');
}

export function ensureMember(req, res, next) {
  if (req.isAuthenticated() && (req.user.is_member || req.user.is_admin)) {
    return next();
  }

  res.status(403).render('error', {
    status: 403,
    title: 'Members Only',
    message: 'You must become a member before applying for admin privileges.',
  });
}


export function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.is_admin) {
    return next();
  }
  
  res.status(403).render('error', {
    status: 403,
    title: 'Forbidden',
    message: 'You must be an admin to access this page.',
  });
}
