//securing dashboard to be accessible by only registered users
module.exports = {
  ensureAuthenticated: function(req, res, next) {
    if(req.isAuthenticated()) {
      return next()
    }
    req.flash(`error_msg`, `Please log in to view this resource`);
    res.redirect(`/login`);
  }
}