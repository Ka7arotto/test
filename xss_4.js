const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    if (!userId) {
        const errorMsg = req.query.error || 'User not found';
        return res.status(404).send(`<h1>Error: ${errorMsg}</h1>`);
    }
    
    res.send(`<h1>User Profile: ${userId}</h1>`);
});

module.exports = app;