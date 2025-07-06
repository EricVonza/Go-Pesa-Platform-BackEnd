// filepath: Go-Pesa-Platform-BackEnd/src/routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user'); 
const authenticateMiddleware = require('../middlewares/authMiddleware'); // Middleware for auth
const router = express.Router();

// Signup Route
router.post('/signup', async (req, res) => {
  const { name, email, username, password } = req.body;

  console.log(`[${new Date().toISOString()}] Signup attempt by: ${email || username}`);

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, username, password: hashedPassword });
    await newUser.save();

    console.log(`[${new Date().toISOString()}] User created successfully: ${email}`);

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Signup error for ${email}: ${error.message}`);
    res.status(500).json({ error: 'Error creating user' });
  }
});

// Login Route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  console.log(`[${new Date().toISOString()}] Login attempt by: ${email}`);

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.warn(`[${new Date().toISOString()}] Login failed - user not found: ${email}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.warn(`[${new Date().toISOString()}] Login failed - invalid password: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    console.log(`[${new Date().toISOString()}] Login successful for: ${email}`);

    res.status(200).json({ token });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Login error for ${email}: ${error.message}`);
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Fetch User Data Route
router.get('/user', authenticateMiddleware, async (req, res) => {
  console.log(`[${new Date().toISOString()}] Fetching user data for userId: ${req.user.id}`);

  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      console.warn(`[${new Date().toISOString()}] User data fetch failed - user not found: ${req.user.id}`);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`[${new Date().toISOString()}] User data fetched for: ${user.email}`);

    res.status(200).json({ name: user.name, email: user.email, username: user.username });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Error fetching user data for ${req.user.id}: ${error.message}`);
    res.status(500).json({ error: 'Error fetching user data' });
  }
});

module.exports = router;
