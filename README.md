# Building a Secure Node.js Authentication System with Express, bcrypt, JWT, and MySQL

Authentication is a critical component of web applications, ensuring that users can securely access their accounts. In this article, we'll explore how to build a secure authentication system using Node.js, Express, bcrypt for password hashing, JWT for token-based authentication, and MySQL for storing user data.

## Project Setup

We begin by setting up our Node.js project with the necessary dependencies:

```
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql2 = require('mysql2/promise');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
```

Here, we import essential libraries such as Express for our web framework, bcrypt for password hashing, JWT for token generation, MySQL for database interactions, and bodyParser for handling JSON requests.

## Database Connection

Next, we establish a connection to our MySQL database using the mysql2 library:

```

const pool = mysql2.createPool({
  host: 'your-host',
  port: your-port,
  user: 'user-name',
  password: 'your-password',
  database: 'database-name',
});


```

The pool object allows us to execute queries and interact with the database.

## Token Configuration

We set up constants for token expiration times and secret keys:

```
const ACCESS_TOKEN_EXPIRY = '15m'; // 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'your-access-secret-key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key';

```

These constants define how long our access and refresh tokens remain valid and the secret keys used for signing and verifying JWT tokens.

## User Registration

When a user registers, we generate a random salt, hash the password with the salt, and store the user's data in the database:

```

app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role_id = 2, first_name, last_name } = req.body;

  try {
    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);

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

```
This endpoint handles user registration by creating a new user in the database.

## User Login

For user login, we verify the entered password against the stored hashed password and generate JWT tokens upon successful authentication:

```
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const storedPasswordHash = user.password;
    const passwordMatch = await bcrypt.compare(password, storedPasswordHash);

    if (passwordMatch) {
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

```

This endpoint validates the user's credentials and issues JWT tokens for subsequent authenticated requests.

## Password Reset request

When a user requests a password reset, we generate a unique reset token, associate it with the user, and set an expiration time:

```
app.post('/api/password/reset/request', async (req, res) => {
  const { email } = req.body;

  try {
    const [users] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = bcrypt.genSaltSync(32);
    const expiresAt = new Date(new Date().getTime() + 1 * 60 * 60 * 1000);

    await pool.query('DELETE FROM password_resets WHERE user_id = ?', [user.user_id]);
    await pool.query('INSERT INTO password_resets (reset_token, user_id, expires_at) VALUES (?, ?, ?)', [resetToken, user.user_id, expiresAt]);

    // TODO: Send an email to the user with a link containing the resetToken

    res.json({ message: 'Password reset requested. Check your email for instructions.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error requesting password reset' });
  }
});

```

This endpoint initiates the password reset process by generating a reset token and storing it in the database.

## Resetting the Password

After verifying the reset token's validity, we generate a new salt, hash the new password, and update the user's password in the database:

```
app.post('/api/password/reset', async (req, res) => {
  const { resetToken, newPassword } = req.body;

  try {
    const [resetRecords] = await pool.query('SELECT user_id, expires_at FROM password_resets WHERE reset_token = ?', [resetToken]);
    const resetRecord = resetRecords[0];

    if (!resetRecord) {
      return res.status(404).json({ message: 'Invalid or expired reset token' });
    }

    const now = new Date();
    const expiresAt = new Date(resetRecord.expires_at);

    if (now > expiresAt) {
      return res.status(401).json({ message: 'Reset token has expired' });
    }

    const [users] = await pool.query('SELECT user_id FROM users WHERE user_id = ?', [resetRecord.user_id]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newSalt = generateSalt();
    const hashedPassword = hashPassword(newPassword, newSalt);

    await pool.query('UPDATE users SET password = ?, salt = ? WHERE user_id = ?', [hashedPassword, newSalt, user.user_id]);
    await pool.query('DELETE FROM password_resets WHERE reset_token = ?', [resetToken]);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

```
This endpoint handles the password reset process by updating the user's password with a new salted hash.

## Conclusion

we've covered the implementation of a secure authentication system using Node.js, Express, bcrypt, JWT, and MySQL. This system provides user registration, login, and password reset functionalities while ensuring data security through proper encryption and token-based authentication

Refer server.js file for entire code