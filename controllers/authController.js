const bcrypt = require('bcrypt');
const { db } = require('../config/firebaseConfig');

// Máximo número de intentos fallidos permitidos antes de bloquear la cuenta
const MAX_LOGIN_ATTEMPTS = 5;

// Registrar inicio de sesión en el historial
exports.registerLoginHistory = async (username) => {
    const timestamp = new Date().toISOString();
    try {
        const userDoc = db.collection('users').doc(username);
        const user = await userDoc.get();
        if (user.exists) {
            const loginHistory = user.data().loginHistory || [];
            loginHistory.push(timestamp);
            await userDoc.update({ loginHistory });
        }
    } catch (error) {
        console.error('Error registrando el historial de inicio de sesión:', error);
    }
};

// Procesar intento de inicio de sesión
exports.processLoginAttempt = async (username) => {
    try {
        const userDoc = db.collection('users').doc(username);
        const user = await userDoc.get();
        if (user.exists) {
            const userData = user.data();
            
            // Verificar si la cuenta está bloqueada
            if (userData.isLocked) {
                return { success: false, message: 'La cuenta está bloqueada debido a múltiples intentos fallidos. Contacta al administrador.' };
            }

            // Incrementar el número de intentos fallidos
            let loginAttempts = userData.loginAttempts || 0;
            loginAttempts += 1;

            // Bloquear la cuenta si supera el número máximo de intentos fallidos
            if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                await userDoc.update({
                    loginAttempts,
                    isLocked: true
                });
                return { success: false, message: 'Cuenta bloqueada por múltiples intentos fallidos.' };
            } else {
                // Actualizar el número de intentos fallidos
                await userDoc.update({
                    loginAttempts
                });
                return { success: false, message: 'Credenciales incorrectas. Intento ' + loginAttempts + ' de ' + MAX_LOGIN_ATTEMPTS + '.' };
            }
        } else {
            return { success: false, message: 'Usuario no encontrado.' };
        }
    } catch (error) {
        console.error('Error al procesar intento de inicio de sesión:', error);
        return { success: false, message: 'Error al procesar el inicio de sesión.' };
    }
};

// Reiniciar intentos de inicio de sesión
exports.resetLoginAttempts = async (username) => {
    try {
        const userDoc = db.collection('users').doc(username);
        const user = await userDoc.get();
        if (user.exists) {
            await userDoc.update({
                loginAttempts: 0,
                isLocked: false
            });
        }
    } catch (error) {
        console.error('Error al reiniciar los intentos de inicio de sesión:', error);
    }
};

// Registrar un nuevo usuario
exports.registerUser = async (req, res) => {
    const { username, password } = req.body;
    if (!isPasswordValid(password)) {
        req.flash('error', 'La contraseña no cumple con los requisitos de seguridad.');
        return res.redirect('/auth/register');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection('users').doc(username).set({
            username,
            password: hashedPassword,
            loginAttempts: 0,
            isLocked: false
        });
        req.flash('success', 'Usuario creado exitosamente.');
        res.redirect('/auth/dashboard');
    } catch (error) {
        req.flash('error', 'Error al crear el usuario.');
        res.redirect('/auth/register');
    }
};

// Validar la política de contraseñas
const isPasswordValid = (password) => {
    // Ejemplo: longitud mínima 8, al menos un número, una letra mayúscula y un carácter especial
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/;
    return passwordRegex.test(password);
};

// Actualizar la contraseña del usuario
exports.updatePassword = async (req, res) => {
    const { password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection('users').doc(req.user.username).update({
            password: hashedPassword
        });
        req.flash('success', 'Contraseña actualizada exitosamente.');
        res.redirect('/auth/dashboard');
    } catch (error) {
        req.flash('error', 'Error al actualizar la contraseña.');
        res.redirect('/auth/profile');
    }
};

// Renderizar la vista de login
exports.renderLogin = (req, res) => {
    res.render('login', { csrfToken: req.csrfToken() });
};

// Renderizar la vista de registro
exports.renderRegister = (req, res) => {
    res.render('register', { csrfToken: req.csrfToken() });
};

// Renderizar la vista de perfil
exports.renderProfile = (req, res) => {
    res.render('profile', { user: req.user, csrfToken: req.csrfToken() });
};

// Cerrar sesión
exports.logoutUser = (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.clearCookie('connect.sid');
        res.redirect('/auth/login');
    });
};
