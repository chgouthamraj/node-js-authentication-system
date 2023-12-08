const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql2 = require('mysql2/promise');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Database connection
const pool = mysql2.createPool({
  host: 'your-host',
  port: 3306,
  user: 'user-name',
  password: 'your-password',
  database: 'database-name',
});

// Set the token expiry times
const ACCESS_TOKEN_EXPIRY = '15m'; // 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days

// Secret keys for JWT tokens
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'your-access-secret-key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key';

// Generate JWT token
const generateToken = (userId, secret, expiresIn) => {
  return jwt.sign({ userId }, secret, { expiresIn });
};

// Function to generate a random salt
const generateSalt = () => {
  return bcrypt.genSaltSync(10);
};

// Function to hash the password with the provided salt
const hashPassword = (password, salt) => {
  return bcrypt.hashSync(password, salt);
};

// Register user
app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role_id = 2, first_name, last_name } = req.body;

  try {
    // Generate a random salt
    const salt = generateSalt();

    // Hash password with the generated salt
    const hashedPassword = hashPassword(password, salt);

    // Create user
    await pool.query('INSERT INTO users (username, email, password, salt, role_id, first_name, last_name) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      username,
      email,
      hashedPassword,
      salt,
      role_id,
      first_name,
      last_name,
    ]);

    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Login user
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const storedPasswordHash = user.password;

    // Compare the provided password with the stored hash using bcrypt
    const passwordMatch = await bcrypt.compare(password, storedPasswordHash);

    if (passwordMatch) {
      // Generate access and refresh tokens
      const accessToken = generateToken(user.user_id, ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRY);
      const refreshToken = generateToken(user.user_id, REFRESH_TOKEN_SECRET, REFRESH_TOKEN_EXPIRY);

      res.status(200).json({ message: 'Login successful', accessToken, refreshToken });
    } else {
      res.status(401).json({ message: 'Incorrect password' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error during login' });
  }
});

// Request password reset
app.post('/api/password/reset/request', async (req, res) => {
  const { email } = req.body;

  try {
    // Find user by email
    const [users] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a unique reset token and set the expiration time
    const resetToken = bcrypt.genSaltSync(32);
    const expiresAt = new Date(new Date().getTime() + 1 * 60 * 60 * 1000); // 1 hour in the future

    // Delete any existing reset tokens for the user
    await pool.query('DELETE FROM password_resets WHERE user_id = ?', [user.user_id]);

    // Save the new reset token in the password_resets table
    await pool.query('INSERT INTO password_resets (reset_token, user_id, expires_at) VALUES (?, ?, ?)', [resetToken, user.user_id, expiresAt]);

    // TODO: Send an email to the user with a link containing the resetToken

    res.json({ message: 'Password reset requested. Check your email for instructions.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error requesting password reset' });
  }
});

// Reset password
app.post('/api/password/reset', async (req, res) => {
  const { resetToken, newPassword } = req.body;

  try {
    // Find the user associated with the reset token
    const [resetRecords] = await pool.query('SELECT user_id, expires_at FROM password_resets WHERE reset_token = ?', [resetToken]);

    const resetRecord = resetRecords[0];

    if (!resetRecord) {
      return res.status(404).json({ message: 'Invalid or expired reset token' });
    }

    // Check if the reset token has expired
    const now = new Date();
    const expiresAt = new Date(resetRecord.expires_at);

    if (now > expiresAt) {
      return res.status(401).json({ message: 'Reset token has expired' });
    }

    // Check if the user still exists
    const [users] = await pool.query('SELECT user_id FROM users WHERE user_id = ?', [resetRecord.user_id]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a new salt
    const newSalt = generateSalt();

    // Update the user's password in the users table with the new salt
    const hashedPassword = hashPassword(newPassword, newSalt);
    await pool.query('UPDATE users SET password = ?, salt = ? WHERE user_id = ?', [hashedPassword, newSalt, user.user_id]);

    // Remove the used reset token from the password_resets table
    await pool.query('DELETE FROM password_resets WHERE reset_token = ?', [resetToken]);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

const PORT = process.env.HTTP_PORT || 3001;

app.listen(PORT, () => {
  console.log(`HTTP server started! Listening on port ${PORT}`);
});
