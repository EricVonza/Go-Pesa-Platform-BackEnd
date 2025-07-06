const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next(); // Pass control to the next middleware or route handler
  } catch (error) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

module.exports = authenticate;