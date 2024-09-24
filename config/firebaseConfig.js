// config/firebaseConfig.js
const admin = require('firebase-admin');
const path = require('path');
require('dotenv').config();
const serviceAccount = require(path.resolve(process.env.FIREBASE_CREDENTIALS));

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://app-clientes-15ea3.firebaseio.com"
});

const db = admin.firestore();

module.exports = { admin, db };
