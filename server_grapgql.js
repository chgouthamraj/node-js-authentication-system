const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql2 = require('mysql2/promise');
const bodyParser = require('body-parser');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');

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

// Define GraphQL schema
const schema = buildSchema(`
  type User {
    user_id: ID!
    username: String!
    email: String!
    role_id: Int!
    first_name: String!
    last_name: String!
  }

  type Query {
    getUserById(user_id: ID!): User
  }

  type Mutation {
    registerUser(username: String!, email: String!, password: String!, role_id: Int, first_name: String!, last_name: String!): String
    loginUser(email: String!, password: String!): TokenResponse
    requestPasswordReset(email: String!): String
    resetPassword(resetToken: String!, newPassword: String!): String
  }

  type TokenResponse {
    message:String
    accessToken: String
    refreshToken: String
  }
`);

// Root resolver
const root = {
  getUserById: async ({ user_id }) => {
    const [users] = await pool.query('SELECT * FROM users WHERE user_id = ?', [user_id]);
    return users[0];
  },
  registerUser: async ({ username, email, password, role_id, first_name, last_name }) => {
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

      return 'User registered successfully';
    } catch (error) {
      console.error(error);
      throw new Error('Error registering user');
    }
  },
  loginUser: async ({ email, password }) => {
    try {
      // Your existing login logic
      const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      const user = users[0];

      if (user.length === 0) {
        throw new Error('User not found');
      }

      const storedPasswordHash = user.password;

      // Compare the provided password with the stored hash using bcrypt
      const passwordMatch = await bcrypt.compare(password, storedPasswordHash);

      if (passwordMatch) {
        // Generate access and refresh tokens
        const accessToken = generateToken(user.user_id, ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRY);
        const refreshToken = generateToken(user.user_id, REFRESH_TOKEN_SECRET, REFRESH_TOKEN_EXPIRY);

        return { message: 'Login successful', accessToken, refreshToken };
      } else {
        throw new Error('Incorrect password');
      }
    } catch (error) {
      console.error(error);
      throw new Error('Error during login');
    }
  },
  requestPasswordReset: async ({ email }) => {
    try {
      const [users] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email]);
      const user = users[0];

      if (!user) {
        return 'User not found';
      }

      // Generate a unique reset token and set the expiration time
      const resetToken = bcrypt.genSaltSync(32);
      const expiresAt = new Date(new Date().getTime() + 1 * 60 * 60 * 1000); // 1 hour in the future

      // Delete any existing reset tokens for the user
      await pool.query('DELETE FROM password_resets WHERE user_id = ?', [user.user_id]);

      // Save the new reset token in the password_resets table
      await pool.query('INSERT INTO password_resets (reset_token, user_id, expires_at) VALUES (?, ?, ?)', [resetToken, user.user_id, expiresAt]);

      // TODO: Send an email to the user with a link containing the resetToken
      return 'Password reset requested. Check your email for instructions.';
    } catch (error) {
      console.error(error);
      throw new Error('Error requesting password reset');
    }
  },
  resetPassword: async ({ resetToken, newPassword }) => {
    try {
      // Find the user associated with the reset token
      const [resetRecords] = await pool.query('SELECT user_id, expires_at FROM password_resets WHERE reset_token = ?', [resetToken]);

      const resetRecord = resetRecords[0];

      if (!resetRecord) {
        return 'Invalid or expired reset token';
      }

      // Check if the reset token has expired
      const now = new Date();
      const expiresAt = new Date(resetRecord.expires_at);

      if (now > expiresAt) {
        return 'Reset token has expired';
      }

      // Check if the user still exists
      const [users] = await pool.query('SELECT user_id FROM users WHERE user_id = ?', [resetRecord.user_id]);
      const user = users[0];

      if (!user) {
        return 'User not found';
      }

      // Generate a new salt
      const newSalt = generateSalt();

      // Update the user's password in the users table with the new salt
      const hashedPassword = hashPassword(newPassword, newSalt);
      await pool.query('UPDATE users SET password = ?, salt = ? WHERE user_id = ?', [hashedPassword, newSalt, user.user_id]);

      // Remove the used reset token from the password_resets table
      await pool.query('DELETE FROM password_resets WHERE reset_token = ?', [resetToken]);
      return 'Password updated successfully';
    } catch (error) {
      console.error(error);
      throw new Error('Error resetting password');
    }
  },
};

// GraphQL endpoint
app.use(
  '/graphql',
  graphqlHTTP({
    schema: schema,
    rootValue: root,
    graphiql: true, // Enable the GraphQL interactive API explorer
  }),
);

const PORT = process.env.HTTP_PORT || 3001;

app.listen(PORT, () => {
  console.log(`HTTP server started! Listening on port ${PORT}`);
});
