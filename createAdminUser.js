// createAdminUser.js
const bcrypt = require('bcrypt');
const { db } = require('./config/firebaseConfig'); // Asegúrate de que la ruta a firebaseConfig.js es correcta

// Configuración para el usuario "0"
const adminUsername = 'admin';
const adminPassword = 'erickDiaz04!'; // Cambia esta contraseña por una segura

async function createAdminUser() {
    try {
        // Verificar si el usuario ya existe
        const userDoc = db.collection('users').doc(adminUsername);
        const user = await userDoc.get();
        if (user.exists) {
            console.log('El usuario administrador ya existe.');
            return;
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(adminPassword, 10);

        // Crear el usuario administrador en la base de datos
        await userDoc.set({
            username: adminUsername,
            password: hashedPassword,
            loginAttempts: 0,
            isLocked: false
        });

        console.log(`Usuario administrador creado con éxito: ${adminUsername}`);
    } catch (error) {
        console.error('Error al crear el usuario administrador:', error);
    }
}

createAdminUser();
