// middleware/authMiddleware.js
module.exports = {
    ensureAuthenticated: (req, res, next) => {
        if (req.isAuthenticated()) {
            return next();
        }
        res.redirect('/login');
    }
};
// Middleware para controlar el tiempo de inactividad
exports.trackUserActivity = (req, res, next) => {
    const MAX_INACTIVITY_TIME = 15 * 60 * 1000; // 15 minutos

    if (req.session.lastActivity && (Date.now() - req.session.lastActivity) > MAX_INACTIVITY_TIME) {
        // Cierra la sesión si el usuario está inactivo por más tiempo del permitido
        return req.logout(() => {
            res.redirect('/auth/login');
        });
    }
    req.session.lastActivity = Date.now();
    next();
};
