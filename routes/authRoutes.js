const express = require('express');
const passport = require('passport');
const router = express.Router();
const { registerUser, logoutUser, renderLogin, renderRegister, renderProfile, updatePassword, registerLoginHistory } = require('../controllers/authController');
const { db } = require('../config/firebaseConfig'); // Asegúrate de importar db si se usa en otras rutas

// Ruta para renderizar la vista de login
router.get('/login', renderLogin);

// Ruta para renderizar la vista de registro
router.get('/register', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    renderRegister(req, res);
});

// Ruta para renderizar la vista de perfil
router.get('/profile', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    renderProfile(req, res);
});

// Ruta para autenticación
router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            req.flash('error', info.message || 'Credenciales incorrectas.');
            return res.redirect('/auth/login');
        }

        // Iniciar sesión y registrar el historial de inicio de sesión
        req.logIn(user, async (err) => {
            if (err) {
                return next(err);
            }
            await registerLoginHistory(user.username);
            return res.redirect('/auth/dashboard');
        });
    })(req, res, next);
});

// Ruta para registrar un nuevo usuario
router.post('/register', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    registerUser(req, res);
});

// Ruta para actualizar la contraseña
router.post('/update-password', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    updatePassword(req, res);
});

// Ruta del dashboard (protegida)
router.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    res.render('dashboard', { csrfToken: req.csrfToken() });
});

// Ruta para cerrar sesión
router.post('/logout', logoutUser);

// Ruta para mostrar el historial de sesiones
router.get('/login-history', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    const userDoc = db.collection('users').doc(req.user.username);
    userDoc.get().then(user => {
        if (user.exists) {
            const loginHistory = user.data().loginHistory || [];
            res.render('loginHistory', { loginHistory });
        } else {
            res.render('loginHistory', { loginHistory: [] });
        }
    }).catch(error => {
        console.error('Error obteniendo el historial de inicio de sesión:', error);
        res.render('loginHistory', { loginHistory: [] });
    });
});

module.exports = router;
