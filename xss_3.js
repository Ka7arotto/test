const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let comments = [];

app.get('/comments', (req, res) => {
    let html = '<h1>User Comments</h1>';
    comments.forEach(comment => {
        html += `<div><strong>${comment.user}:</strong> ${comment.text}</div>`;
    });
    res.send(html);
});

app.post('/comments', (req, res) => {
    const { user, text } = req.body;
    comments.push({ user, text });
    res.redirect('/comments');
});

module.exports = app;