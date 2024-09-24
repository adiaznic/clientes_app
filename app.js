// app.js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const flash = require('connect-flash');
const path = require('path');

dotenv.config();

const app = express();
const authRoutes = require('./routes/authRoutes');
require('./config/passportConfig')(passport);

// Configuración del motor de vistas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Configuración de la sesión
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 3600000 // 1 hora
    }
}));

// Middleware para flash
app.use(flash());

// CSRF Protection
app.use(csrf({ cookie: true }));

// Añadir token CSRF al objeto de respuesta para cada solicitud
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    res.locals.error = req.flash('error'); // Añadir mensajes de error a las variables locales
    res.locals.success = req.flash('success'); // Añadir mensajes de éxito a las variables locales
    next();
});

app.use(passport.initialize());
app.use(passport.session());

// Rutas
app.use('/auth', authRoutes);

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
