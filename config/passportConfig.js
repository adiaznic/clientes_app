// config/passportConfig.js
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { db } = require('./firebaseConfig'); // Asegúrate de importar la configuración de Firebase

// Máximo número de intentos fallidos permitidos antes de bloquear la cuenta
const MAX_LOGIN_ATTEMPTS = 5;

module.exports = function(passport) {
    passport.use(new LocalStrategy(async (username, password, done) => {
        try {
            // Buscar el usuario en la base de datos
            const userSnapshot = await db.collection('users').doc(username).get();
            if (!userSnapshot.exists) {
                return done(null, false, { message: 'Usuario no encontrado.' });
            }

            const user = userSnapshot.data();

            // Verificar si la cuenta está bloqueada
            if (user.isLocked) {
                return done(null, false, { message: 'La cuenta está bloqueada debido a múltiples intentos fallidos. Contacta al administrador.' });
            }

            // Comparar la contraseña hasheada
            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                // Reiniciar intentos fallidos después de un inicio de sesión exitoso
                await db.collection('users').doc(username).update({
                    loginAttempts: 0,
                    isLocked: false
                });
                return done(null, user); // Autenticación exitosa
            } else {
                // Incrementar el número de intentos fallidos
                let loginAttempts = user.loginAttempts || 0;
                loginAttempts += 1;

                // Bloquear la cuenta si supera el número máximo de intentos fallidos
                if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                    await db.collection('users').doc(username).update({
                        loginAttempts,
                        isLocked: true
                    });
                    return done(null, false, { message: 'Cuenta bloqueada por múltiples intentos fallidos.' });
                } else {
                    // Actualizar el número de intentos fallidos
                    await db.collection('users').doc(username).update({
                        loginAttempts
                    });
                    return done(null, false, { message: `Contraseña incorrecta. Intento ${loginAttempts} de ${MAX_LOGIN_ATTEMPTS}.` });
                }
            }
        } catch (error) {
            console.error('Error durante la autenticación:', error);
            return done(error);
        }
    }));

    // Serializar el usuario
    passport.serializeUser((user, done) => {
        done(null, user.username);
    });

    // Deserializar el usuario
    passport.deserializeUser(async (username, done) => {
        try {
            const userSnapshot = await db.collection('users').doc(username).get();
            if (userSnapshot.exists) {
                done(null, userSnapshot.data());
            } else {
                done(new Error('Usuario no encontrado'), null);
            }
        } catch (error) {
            console.error('Error durante la deserialización:', error);
            done(error, null);
        }
    });
};
