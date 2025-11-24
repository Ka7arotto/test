const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});
app.get('/', (req, res) => {
    res.send('<h1>Welcome</h1>');
});
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Missing credentials' });
    }
});
app.get('/users', (req, res) => {
    res.json([{ id: 1, name: 'User1' }, { id: 2, name: 'User2' }]);
});
app.get('/profile/:id', (req, res) => {
    const { id } = req.params;
    res.json({ id, email: 'user@example.com' });
});
app.post('/register', (req, res) => {
    const { email, pass } = req.body;
    if (email && pass) {
        res.json({ registered: true });
    } else {
        res.status(400).json({ error: 'Invalid data' });
    }
});
app.put('/update/:id', (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    res.json({ updated: id, name });
});
app.get('/search', (req, res) => {
    const { q } = req.query;
    if (!q) {
        return res.status(400).send('<h3>Query required</h3>');
    }
    let html = `<h3>Search results for: ${q}</h3>`;
    html += '<p>Checking database...</p>';
    res.send(html);
});
app.delete('/delete/:id', (req, res) => {
    const { id } = req.params;
    res.json({ deleted: id });
});
app.get('/api/info', (req, res) => {
    res.json({ version: '1.0', status: 'ok' });
});
app.post('/api/upload', (req, res) => {
    const { file } = req.body;
    if (file) {
        res.json({ uploaded: true });
    } else {
        res.status(400).json({ error: 'No file' });
    }
});
app.use((req, res) => {
    res.status(404).send('<h1>Not Found</h1>');
});
app.listen(3000, () => {
    console.log('Server running on port 3000');
});