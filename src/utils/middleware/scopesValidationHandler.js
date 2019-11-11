
function scopesValidationHandler(allowedScopes) {
  return function(req, res, next) {
    // if user exist and has scopes
    if(!req.user || (req.user && !req.user.scopes)) {
      next(new Error('Missing scopes'));
    }

    // verify if the user's scope allows the necessary scope
    const hasAccess = allowedScopes
      .map(allowedScopes => req.user.scopes.includes(allowedScopes))
      .find(allowed => Boolean(allowed));

    if (hasAccess) {
      next();
    } else {
      next(new Error('Insufficient scopes'));
    }
  }
}

module.exports = scopesValidationHandler;