// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');


// Load environment variables from .env file
require('dotenv').config();


// Initialize Express app
const app = express();
const PORT = process.env.PORT || 8080;

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET_KEY;

// Middleware to parse JSON requests
app.use(express.json());

// Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});


// Test the database connection using async/await
const testDbConnection = async () => {
  try {
      const connection = await db.getConnection();  // Get a connection from the pool
      console.log('Connected to the database');
      connection.release();  // Release the connection back to the pool
  } catch (err) {
      console.error('Error connecting to the database:', err.message);
  }
};

// Call the function to test the database connection
testDbConnection();


// Middleware for user authentication
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
};


// Middleware for role-based access control
const authorizeRole = (role) => (req, res, next) => {
    if (req.user.role !== role) {
        return res.status(403).json({ message: 'Forbidden' });
    }
    next();
};



// User registration
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role]);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});


// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});



// CRUD operations for tasks

// Create a task
app.post('/tasks', authenticateToken, async (req, res) => {
    const { title, description, status } = req.body;
    if (!title || !description || !status) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        await db.query('INSERT INTO tasks (title, description, status, user_id) VALUES (?, ?, ?, ?)', [title, description, status, req.user.id]);
        res.status(201).json({ message: 'Task created successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating task', error });
    }
});


// Get all tasks by logged in user
app.get('/tasks', authenticateToken, async (req, res) => {
    try {
        const [tasks] = await db.query('SELECT * FROM tasks WHERE user_id = ?', [req.user.id]);
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving tasks', error });
    }
});

// Get all tasks (admin only)
app.get('/admin/tasks', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
      // Fetch all tasks from the database
      const [tasks] = await db.query('SELECT * FROM tasks');
      res.json(tasks); // Send all tasks to the admin
  } catch (error) {
      res.status(500).json({ message: 'Error retrieving tasks', error });
  }
});



// Update a task
app.put('/tasks/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, description, status } = req.body;
    if (!title || !description || !status) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const [result] = await db.query('UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ? AND user_id = ?', [title, description, status, id, req.user.id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }

        res.json({ message: 'Task updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating task', error });
    }
});


// Delete a task
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const [result] = await db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, req.user.id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }

        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting task', error });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});