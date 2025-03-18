// Main Express server setup for user authentication
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const { connectToDB } = require("./db/db.connect.js");
const User = require("./models/user.model.js");
const Job = require("./models/job.model.js");

const app = express();
const PORT = process.env.PORT || 4000;

// Enable JSON parsing and cookie handling
app.use(express.json());
app.use(cookieParser());

// Configure CORS to allow credentials - required for HTTP-only cookies to work
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
  })
);

// Critical security check - prevent server startup without proper secrets
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error(
    "CRITICAL ERROR: JWT secrets not set in environment variables!"
  );
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

connectToDB();

// Generate separate access and refresh tokens for enhanced security
// Short-lived access token minimizes damage if compromised
// Long-lived refresh token enables seamless user experience
const generateTokens = (user) => {
  const payload = {
    id: user._id,
    username: user.username || user.email,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });

  const refreshToken = jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

// Store tokens in HTTP-only cookies instead of localStorage
// Protects against XSS attacks since JavaScript cannot access HTTP-only cookies
const setAuthCookies = (res, accessToken, refreshToken) => {
  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
    sameSite: "strict", // Prevents CSRF attacks
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token", // Only sent to specific path - reduces attack surface
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

// Clean removal of auth cookies for proper logout
const clearAuthCookies = (res) => {
  res.cookie("access_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 0,
  });

  res.cookie("refresh_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token",
    maxAge: 0,
  });
};

// Middleware to verify token and protect routes
// Adds user info to request object for authorized routes
const authenticateToken = (req, res, next) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(accessToken, JWT_SECRET);
    req.user = decoded; // Makes user data available to route handlers
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      // Special handling for expired tokens to trigger refresh flow in frontend
      return res
        .status(401)
        .json({ message: "Token expired", code: "TOKEN_EXPIRED" });
    }
    return res.status(403).json({ message: "Invalid token" });
  }
};

// Placeholder for rate limiting - would implement with express-rate-limit in production
// Prevents brute force attacks on login endpoints
const loginLimiter = (req, res, next) => {
  next();
};

// User registration with validation and security checks
app.post("/auth/register", async (req, res) => {
  const { username, name, email, password } = req.body;

  // Input validation to prevent bad data and improve security
  if (!username || !name || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (email && !emailRegex.test(email)) {
    return res
      .status(400)
      .json({ message: "Please provide a valid email address" });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  }

  try {
    // Check for existing users to prevent duplicates
    const existingUser = await User.findOne({
      $or: [{ username }, { email: email || null }],
    });

    if (existingUser) {
      return res.status(400).json({
        message:
          existingUser.username === username
            ? "Username already exists"
            : "Email already exists",
      });
    }

    // Hash password before storage - never store plain text passwords
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      name,
      email: email || null,
      password: hashedPassword,
    });

    await newUser.save();

    // Auto-login after registration by generating tokens
    const { accessToken, refreshToken } = generateTokens(newUser);
    setAuthCookies(res, accessToken, refreshToken);

    // Return user data without sensitive fields
    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      name: newUser.name,
      email: newUser.email,
    };

    res.status(201).json({
      message: "User registered successfully",
      user: userResponse,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering user",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

// User login with username/email and password
app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide username and password" });
  }

  try {
    // Support login with either username or email for flexibility
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Special handling for social login accounts that don't have passwords
    if (!user.password) {
      return res.status(401).json({
        message:
          "This account uses social login. Please sign in with the appropriate provider.",
      });
    }

    // Verify password using bcrypt to compare against hashed version
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Create and set auth tokens
    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    // Return user data without sensitive fields
    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
    };

    res.status(200).json({
      message: "Logged in successfully",
      user: userResponse,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      message: "Error logging in",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

// Token refresh endpoint - allows getting new access token without re-login
// Enables persistent sessions with short-lived access tokens
app.post("/auth/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    // Verify refresh token - uses different secret than access tokens
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    // Find user to ensure they still exist and have access
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Generate fresh tokens
    const tokens = generateTokens(user);
    setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    res.status(200).json({ message: "Token refreshed successfully" });
  } catch (error) {
    // Clear cookies on failure to force re-login
    clearAuthCookies(res);

    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Refresh token expired, please login again" });
    }

    return res.status(403).json({ message: "Invalid refresh token" });
  }
});

// Get current user profile - protected route example
app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    // Find user and exclude sensitive fields
    const user = await User.findById(req.user.id).select("-password -__v");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({
      message: "Error fetching profile",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

// Logout - clears auth cookies
app.post("/auth/logout", (req, res) => {
  clearAuthCookies(res);
  res.status(200).json({ message: "Logged out successfully" });
});

// Generate secure random state parameter to prevent CSRF in OAuth flow
const generateOAuthState = () => {
  return crypto.randomBytes(32).toString("hex");
};

// Store states in memory - would use Redis in production for scalability
const oauthStates = new Map();

// Google OAuth flow - initiate authentication
app.get("/auth/google", (req, res) => {
  // Create and store state parameter to verify callback is legitimate
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  // Build Google OAuth URL with required parameters
  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.append("client_id", process.env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/google/callback`
  );
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("scope", "profile email");
  authUrl.searchParams.append("state", state);

  // Redirect user to Google's authorization page
  res.redirect(authUrl.toString());
});

// Google OAuth callback - handles the response from Google
app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;

  // Verify state to prevent CSRF attacks
  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  // Clean up used state
  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=google_auth_failed`
    );
  }

  try {
    // Exchange auth code for access token
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.API_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }
    );

    const { access_token } = tokenResponse.data;

    // Use access token to get user info from Google
    const userInfoResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: { Authorization: `Bearer ${access_token}` },
      }
    );

    const googleUserInfo = userInfoResponse.data;

    // Find or create user based on Google ID
    let user = await User.findOne({ googleId: googleUserInfo.id });

    if (!user) {
      // Try to link to existing account with same email 
      if (googleUserInfo.email) {
        const existingUser = await User.findOne({
          email: googleUserInfo.email,
        });
        if (existingUser) {
          // Link Google account to existing user
          existingUser.googleId = googleUserInfo.id;
          existingUser.avatar = existingUser.avatar || googleUserInfo.picture;
          user = await existingUser.save();
        }
      }

      // Create new user if no matching account found
      if (!user) {
        user = new User({
          googleId: googleUserInfo.id,
          name: googleUserInfo.name,
          email: googleUserInfo.email,
          username: googleUserInfo.email
            ? googleUserInfo.email.split("@")[0]
            : `user_${googleUserInfo.id}`,
          avatar: googleUserInfo.picture,
        });

        await user.save();
      }
    }

    // Generate our own JWT tokens instead of using Google tokens directly
    // This gives us control over the session lifecycle
    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    // Redirect back to frontend with success
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?provider=google`);
  } catch (error) {
    console.error("Google auth error:", error);
    res.redirect(`${process.env.FRONTEND_URL}/auth?error=google_auth_failed`);
  }
});

// GitHub OAuth flow - similar structure to Google OAuth
app.get("/auth/github", (req, res) => {
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.append("client_id", process.env.GITHUB_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/github/callback`
  );
  authUrl.searchParams.append("scope", "user:email");
  authUrl.searchParams.append("state", state);

  res.redirect(authUrl.toString());
});

// GitHub OAuth callback
app.get("/auth/github/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=github_auth_failed`
    );
  }

  try {
    // Exchange code for token
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${process.env.API_URL}/auth/github/callback`,
      },
      {
        headers: { Accept: "application/json" },
      }
    );

    const { access_token } = tokenResponse.data;

    // Get user info
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `token ${access_token}` },
    });

    const githubUserInfo = userResponse.data;

    // GitHub might not provide email in basic profile - need separate request
    let email = githubUserInfo.email;

    if (!email) {
      try {
        // Get user's emails from GitHub API if not in basic profile
        const emailResponse = await axios.get(
          "https://api.github.com/user/emails",
          {
            headers: { Authorization: `token ${access_token}` },
          }
        );

        // Find primary email
        const primaryEmail = emailResponse.data.find((e) => e.primary);
        if (primaryEmail) {
          email = primaryEmail.email;
        } else if (emailResponse.data.length > 0) {
          email = emailResponse.data[0].email;
        }
      } catch (emailError) {
        console.error("Error fetching GitHub emails:", emailError);
      }
    }

    // Find or create user based on GitHub ID
    let user = await User.findOne({ githubId: githubUserInfo.id });

    if (!user) {
      // Try to link with existing email account
      if (email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          existingUser.githubId = githubUserInfo.id;
          existingUser.avatar =
            existingUser.avatar || githubUserInfo.avatar_url;
          user = await existingUser.save();
        }
      }

      // Create new user if needed
      if (!user) {
        user = new User({
          githubId: githubUserInfo.id,
          name: githubUserInfo.name || githubUserInfo.login,
          email: email,
          username:
            githubUserInfo.login ||
            (email ? email.split("@")[0] : `user_${githubUserInfo.id}`),
          avatar: githubUserInfo.avatar_url,
        });

        await user.save();
      }
    }

    // Generate JWT tokens and set cookies
    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    // Redirect to frontend
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?provider=github`);
  } catch (error) {
    console.error("GitHub auth error:", error);
    res.redirect(`${process.env.FRONTEND_URL}/auth?error=github_auth_failed`);
  }
});

// Cleanup old OAuth states to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of oauthStates.entries()) {
    // Remove states older than 10 minutes
    if (now - data.timestamp > 10 * 60 * 1000) {
      oauthStates.delete(state);
    }
  }
}, 5 * 60 * 1000); // Run every 5 minutes

// 404 handler for undefined routes
app.use((req, res, next) => {
  res.status(404).json({ message: "Resource not found" });
});

// Global error handler for uncaught exceptions
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? error.message : null,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});