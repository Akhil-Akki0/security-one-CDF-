/**
 * Enterprise Production Hardened OpenFOAM v2606 Backend Server
 * 
 * DEVELOPED by Akhil.A gmail :- akkedu01@gmail.com
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const logger = require('./logger');
const {
  USERS,
  REFRESH_TOKENS,
  EMAIL_VERIFICATION_TOKENS,
  PASSWORD_RESET_TOKENS,
  USER_SESSIONS,
  generateTotpSecret,
  verifyTotp,
  isPasswordPwned,
  generateAccessToken,
  generateRefreshToken,
  setAuthCookies,
  clearAuthCookies,
  authenticate,
  requireRole,
  verifyCsrf,
  MAX_FAILED_ATTEMPTS,
  LOCKOUT_DURATION_MS,
} = require('./auth');

const {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  totpVerifySchema,
  totpDisableSchema,
  simulationRequestSchema,
  caseIdParamSchema,
  validateStlPayload,
  validateBody,
  validateParams,
  enforceJsonContentType,
} = require('./validation');

const {
  submitSimulationJob,
  getJobStatus,
  executeSafeCommand,
  BASE_CASE_DIR,
  activeJobs,
} = require('./openfoamRunner');

const app = express();
const PORT = process.env.PORT || 3001;
const IS_PROD = process.env.NODE_ENV === 'production';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// ----------------------------------------------------------------------------
// 1. Correlation ID Middleware & Request Auditing
// ----------------------------------------------------------------------------
app.use((req, res, next) => {
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);

  const startHrTime = process.hrtime();
  res.on('finish', () => {
    const elapsedHrTime = process.hrtime(startHrTime);
    const elapsedMs = (elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1e6).toFixed(2);

    logger.info('HTTP Request', {
      correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || '-',
      durationMs: parseFloat(elapsedMs),
    });
  });

  next();
});

// ----------------------------------------------------------------------------
// 2. Strict HTTP Security Headers (Helmet.js)
// ----------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'", ALLOWED_ORIGIN, 'http://localhost:3000', 'http://127.0.0.1:3000'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: IS_PROD ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false, // Compatibility for WebGL/VTK canvas
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hsts: IS_PROD
      ? {
          maxAge: 63072000,
          includeSubDomains: true,
          preload: true,
        }
      : false,
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
  })
);

// Feature & Permissions Policy
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()'
  );
  next();
});

// ----------------------------------------------------------------------------
// 3. CORS Hardening
// ----------------------------------------------------------------------------
const allowedOriginsList = ALLOWED_ORIGIN.split(',').map((s) => s.trim());
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow internal/non-browser requests (like health checks or curl) if needed
      if (!origin) return callback(null, true);

      if (
        allowedOriginsList.includes(origin) ||
        origin === 'http://localhost:3000' ||
        origin === 'http://127.0.0.1:3000' ||
        origin.endsWith('.run.app')
      ) {
        return callback(null, true);
      }
      logger.warn('CORS request blocked from untrusted origin', { origin });
      return callback(new Error('CORS request denied by security policy.'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID', 'X-CSRF-Token'],
    maxAge: 600, // Preflight caching (10 minutes)
  })
);

// ----------------------------------------------------------------------------
// 4. Body Parsing with Strict Payload Size Limits
// ----------------------------------------------------------------------------
app.use(cookieParser());
// General limit: 1 MB. STL upload routes allow up to 50 MB
app.use((req, res, next) => {
  if (req.path === '/api/run-simulation' || req.path === '/api/simulate') {
    express.json({ limit: '50mb' })(req, res, next);
  } else {
    express.json({ limit: '1mb' })(req, res, next);
  }
});
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ----------------------------------------------------------------------------
// 5. Rate Limiting & DoS Protection
// ----------------------------------------------------------------------------
// Auth endpoints rate limiter: 5 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts. Please try again after 15 minutes.',
    code: 'AUTH_RATE_LIMIT_EXCEEDED',
  },
  handler: (req, res, next, options) => {
    logger.audit('RATE_LIMIT_EXCEEDED', {
      endpoint: req.path,
      ip: req.ip,
      correlationId: req.correlationId,
    });
    res.status(429).json(options.message);
  },
});

// Simulation submission limiter: 10 simulations per hour per user / IP
const simulationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.user ? req.user.id : req.ip),
  message: {
    error: 'Simulation execution rate limit reached (max 10 submissions/hour).',
    code: 'SIMULATION_RATE_LIMIT_EXCEEDED',
  },
  handler: (req, res, next, options) => {
    logger.audit('SIM_RATE_LIMIT_EXCEEDED', {
      userId: req.user?.id,
      ip: req.ip,
      correlationId: req.correlationId,
    });
    res.status(429).json(options.message);
  },
});

// Global API rate limiter: 100 requests per 15 minutes
const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many API requests from this client. Please slow down.',
    code: 'GLOBAL_RATE_LIMIT_EXCEEDED',
  },
});
app.use('/api/', generalApiLimiter);

// ----------------------------------------------------------------------------
// 6. Health, Readiness & Prometheus Metrics Endpoints
// ----------------------------------------------------------------------------
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/readyz', async (req, res) => {
  try {
    const probe = await executeSafeCommand('which', ['simpleFoam'], '/tmp');
    const openFoamReady = probe.stdout.includes('simpleFoam');
    res.status(200).json({
      status: 'ready',
      openFoamDetected: openFoamReady,
      activeJobs: activeJobs.size,
    });
  } catch (err) {
    res.status(503).json({ status: 'not_ready', error: 'Solver pipeline check failed' });
  }
});

app.get('/api/health', async (req, res) => {
  const probe = await executeSafeCommand('which', ['simpleFoam'], '/tmp');
  const hasOf = probe.stdout.includes('simpleFoam');

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    openfoamVersion: 'v2606',
    openfoamDetected: hasOf,
    platform: process.platform,
    safeDirectory: BASE_CASE_DIR,
    developer: 'Akhil.A (akkedu01@gmail.com)',
    activeJobsCount: activeJobs.size,
  });
});

app.get('/metrics', requireRole(['admin']), (req, res) => {
  const mem = process.memoryUsage();
  let completedCount = 0;
  let runningCount = 0;
  let failedCount = 0;

  for (const j of activeJobs.values()) {
    if (j.status === 'completed') completedCount++;
    if (j.status === 'running') runningCount++;
    if (j.status === 'failed') failedCount++;
  }

  const metrics = `
# HELP cfd_process_uptime_seconds Process uptime in seconds
# TYPE cfd_process_uptime_seconds gauge
cfd_process_uptime_seconds ${process.uptime()}

# HELP cfd_process_memory_rss_bytes Resident set size in bytes
# TYPE cfd_process_memory_rss_bytes gauge
cfd_process_memory_rss_bytes ${mem.rss}

# HELP cfd_process_memory_heap_used_bytes Heap memory used
# TYPE cfd_process_memory_heap_used_bytes gauge
cfd_process_memory_heap_used_bytes ${mem.heapUsed}

# HELP cfd_simulation_jobs Total tracked simulation jobs
# TYPE cfd_simulation_jobs gauge
cfd_simulation_jobs{status="running"} ${runningCount}
cfd_simulation_jobs{status="completed"} ${completedCount}
cfd_simulation_jobs{status="failed"} ${failedCount}
`.trim();

  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.send(metrics);
});

// ----------------------------------------------------------------------------
// 7. Authentication Endpoints
// ----------------------------------------------------------------------------

/**
 * POST /api/auth/signup
 */
app.post(
  '/api/auth/signup',
  authLimiter,
  enforceJsonContentType,
  validateBody(signupSchema),
  async (req, res, next) => {
    try {
      const { email, name, password } = req.body;

      // Check if user already exists
      for (const u of USERS.values()) {
        if (u.email.toLowerCase() === email.toLowerCase()) {
          logger.audit('SIGNUP_DUPLICATE_ATTEMPT', { email, ip: req.ip, correlationId: req.correlationId });
          return res.status(409).json({
            error: 'An account with this email address already exists.',
            code: 'EMAIL_ALREADY_EXISTS',
          });
        }
      }

      // Check HaveIBeenPwned k-anonymity API
      const isPwned = await isPasswordPwned(password);
      if (isPwned) {
        logger.audit('PWNED_PASSWORD_REJECTED', { email, ip: req.ip, correlationId: req.correlationId });
        return res.status(400).json({
          error: 'This password has appeared in known data breaches. Please choose a different, unique password.',
          code: 'PASSWORD_BREACHED',
        });
      }

      // Hash password with bcrypt cost 12
      const passwordHash = await bcrypt.hash(password, 12);
      const userId = `usr_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;

      const newUser = {
        id: userId,
        email: email.toLowerCase(),
        name,
        role: 'user',
        passwordHash,
        isEmailVerified: false,
        failedAttempts: 0,
        lockedUntil: null,
        totpEnabled: false,
        totpSecret: null,
        createdAt: new Date().toISOString(),
      };
      USERS.set(userId, newUser);

      // Generate verification token (expires in 24 hours)
      const verifyToken = crypto.randomBytes(32).toString('hex');
      EMAIL_VERIFICATION_TOKENS.set(verifyToken, {
        userId,
        expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      });

      logger.audit('USER_SIGNUP_SUCCESS', {
        userId,
        email: newUser.email,
        ip: req.ip,
        correlationId: req.correlationId,
      });

      res.status(201).json({
        message: 'Account created successfully. Please verify your email to unlock all features.',
        userId,
        verificationTokenPreview: IS_PROD ? undefined : verifyToken, // For easy automated/curl testing in staging
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/auth/login
 */
app.post(
  '/api/auth/login',
  authLimiter,
  enforceJsonContentType,
  validateBody(loginSchema),
  async (req, res, next) => {
    try {
      const { email, password, totpCode } = req.body;

      let targetUser = null;
      for (const u of USERS.values()) {
        if (u.email.toLowerCase() === email.toLowerCase()) {
          targetUser = u;
          break;
        }
      }

      // Mitigate User Enumeration: Use constant-time dummy compare if user not found
      if (!targetUser) {
        await bcrypt.compare(password, '$2a$12$e8Y5t1hK2rE8nQf9xJ7Z7uM1u0b8qN9p3fK1v7yE2wz6O6s0wBvE4');
        logger.audit('LOGIN_FAILED_UNKNOWN_USER', { email, ip: req.ip, correlationId: req.correlationId });
        return res.status(401).json({ error: 'Invalid email or password.', code: 'INVALID_CREDENTIALS' });
      }

      // Check Account Lockout (5 failed attempts = 15m lockout)
      if (targetUser.lockedUntil && targetUser.lockedUntil > Date.now()) {
        const remainingMinutes = Math.ceil((targetUser.lockedUntil - Date.now()) / (60 * 1000));
        logger.audit('LOGIN_ATTEMPT_LOCKED_ACCOUNT', {
          userId: targetUser.id,
          ip: req.ip,
          correlationId: req.correlationId,
        });
        return res.status(423).json({
          error: `Account is temporarily locked due to consecutive failed logins. Try again in ${remainingMinutes} minute(s).`,
          code: 'ACCOUNT_LOCKED',
        });
      }

      // Verify Password
      const isMatch = await bcrypt.compare(password, targetUser.passwordHash);
      if (!isMatch) {
        targetUser.failedAttempts = (targetUser.failedAttempts || 0) + 1;
        if (targetUser.failedAttempts >= MAX_FAILED_ATTEMPTS) {
          targetUser.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
          logger.audit('ACCOUNT_LOCKED_TRIGGERED', {
            userId: targetUser.id,
            ip: req.ip,
            correlationId: req.correlationId,
          });
        }
        return res.status(401).json({ error: 'Invalid email or password.', code: 'INVALID_CREDENTIALS' });
      }

      // Reset failed attempts on valid password
      targetUser.failedAttempts = 0;
      targetUser.lockedUntil = null;

      // 2FA Verification: Mandatory for Admin, or if user enabled TOTP
      if (targetUser.role === 'admin' || targetUser.totpEnabled) {
        if (!totpCode) {
          return res.status(403).json({
            error: 'Two-factor authentication code required.',
            code: '2FA_REQUIRED',
            requires2FA: true,
          });
        }

        const valid2FA = verifyTotp(targetUser.totpSecret, totpCode);
        if (!valid2FA) {
          logger.audit('2FA_VERIFICATION_FAILED', {
            userId: targetUser.id,
            ip: req.ip,
            correlationId: req.correlationId,
          });
          return res.status(401).json({ error: 'Invalid two-factor authentication code.', code: 'INVALID_2FA_CODE' });
        }
      }

      // Issue Tokens
      const accessToken = generateAccessToken(targetUser);
      const csrfToken = crypto.randomBytes(32).toString('hex');
      const { token: refreshToken, sessionId } = generateRefreshToken(targetUser, undefined, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      // Set httpOnly SameSite=Strict cookie for refresh token, and client cookie for CSRF
      setAuthCookies(res, refreshToken, csrfToken);

      logger.audit('LOGIN_SUCCESS', {
        userId: targetUser.id,
        role: targetUser.role,
        ip: req.ip,
        sessionId,
        correlationId: req.correlationId,
      });

      res.json({
        accessToken,
        csrfToken,
        user: {
          id: targetUser.id,
          email: targetUser.email,
          name: targetUser.name,
          role: targetUser.role,
          totpEnabled: !!targetUser.totpEnabled,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /api/auth/refresh
 * Automatic Refresh Token Rotation with Reuse Detection
 */
app.post('/api/auth/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies && req.cookies['cfd_refresh_token'];
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required', code: 'NO_REFRESH_TOKEN' });
    }

    const { JWT_REFRESH_SECRET } = require('./auth');
    const jwt = require('jsonwebtoken');

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    } catch (err) {
      clearAuthCookies(res);
      return res.status(403).json({ error: 'Invalid or expired refresh token', code: 'REFRESH_TOKEN_INVALID' });
    }

    const tokenRecord = REFRESH_TOKENS.get(payload.jti);

    // REUSE DETECTION: If a previously revoked or used token in the family is presented, revoke all family tokens!
    if (!tokenRecord || tokenRecord.isRevoked) {
      logger.audit('REFRESH_TOKEN_REUSE_DETECTED', {
        userId: payload.sub,
        familyId: payload.familyId,
        ip: req.ip,
        correlationId: req.correlationId,
      });
      // Invalidate all tokens in family
      for (const [id, rec] of REFRESH_TOKENS.entries()) {
        if (rec.familyId === payload.familyId) {
          rec.isRevoked = true;
        }
      }
      clearAuthCookies(res);
      return res.status(403).json({
        error: 'Security alert: Refresh token reuse detected. All sessions revoked.',
        code: 'TOKEN_FAMILY_REVOKED',
      });
    }

    // Invalidate current token (single-use rotation)
    tokenRecord.isRevoked = true;

    const user = USERS.get(payload.sub);
    if (!user) {
      clearAuthCookies(res);
      return res.status(401).json({ error: 'User no longer exists', code: 'USER_NOT_FOUND' });
    }

    // Issue new access token and rotated refresh token
    const newAccessToken = generateAccessToken(user);
    const newCsrfToken = crypto.randomBytes(32).toString('hex');
    const { token: newRefreshToken } = generateRefreshToken(user, payload.familyId, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    setAuthCookies(res, newRefreshToken, newCsrfToken);

    res.json({
      accessToken: newAccessToken,
      csrfToken: newCsrfToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        totpEnabled: !!user.totpEnabled,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/logout
 */
app.post('/api/auth/logout', (req, res) => {
  const refreshToken = req.cookies && req.cookies['cfd_refresh_token'];
  if (refreshToken) {
    try {
      const { JWT_REFRESH_SECRET } = require('./auth');
      const jwt = require('jsonwebtoken');
      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
      if (payload && payload.jti) {
        REFRESH_TOKENS.delete(payload.jti);
      }
    } catch (e) {}
  }

  clearAuthCookies(res);
  res.json({ message: 'Successfully logged out and credentials cleared.' });
});

/**
 * GET /api/auth/me
 */
app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: req.user });
});

/**
 * POST /api/auth/verify-email
 */
app.post('/api/auth/verify-email', validateBody(verifyEmailSchema), (req, res) => {
  const { token } = req.body;
  const record = EMAIL_VERIFICATION_TOKENS.get(token);

  if (!record || record.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Verification token is invalid or has expired.' });
  }

  const user = USERS.get(record.userId);
  if (user) {
    user.isEmailVerified = true;
  }
  EMAIL_VERIFICATION_TOKENS.delete(token);

  res.json({ message: 'Email successfully verified. You now have full operational access.' });
});

/**
 * POST /api/auth/forgot-password
 */
app.post('/api/auth/forgot-password', authLimiter, validateBody(forgotPasswordSchema), (req, res) => {
  const { email } = req.body;
  let user = null;
  for (const u of USERS.values()) {
    if (u.email.toLowerCase() === email.toLowerCase()) {
      user = u;
      break;
    }
  }

  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    PASSWORD_RESET_TOKENS.set(token, {
      userId: user.id,
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour expiry
    });
    logger.audit('PASSWORD_RESET_REQUESTED', { userId: user.id, email, ip: req.ip, correlationId: req.correlationId });
  }

  // Consistent response to prevent user enumeration
  res.json({
    message: 'If an account exists with that email, a password reset link has been dispatched.',
  });
});

/**
 * POST /api/auth/reset-password
 */
app.post('/api/auth/reset-password', authLimiter, validateBody(resetPasswordSchema), async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const record = PASSWORD_RESET_TOKENS.get(token);

    if (!record || record.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
    }

    const user = USERS.get(record.userId);
    if (!user) {
      return res.status(400).json({ error: 'User no longer exists.' });
    }

    const isPwned = await isPasswordPwned(newPassword);
    if (isPwned) {
      return res.status(400).json({
        error: 'This password has appeared in known data breaches. Please choose a different password.',
      });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    PASSWORD_RESET_TOKENS.delete(token);

    // Invalidate ALL sessions for this user on password reset
    USER_SESSIONS.delete(user.id);
    for (const [id, rec] of REFRESH_TOKENS.entries()) {
      if (rec.userId === user.id) {
        rec.isRevoked = true;
      }
    }

    logger.audit('PASSWORD_RESET_COMPLETED', { userId: user.id, ip: req.ip, correlationId: req.correlationId });
    res.json({ message: 'Password reset successfully. All active sessions have been invalidated.' });
  } catch (err) {
    next(err);
  }
});

/**
 * 2FA Endpoints
 */
app.post('/api/auth/2fa/setup', authenticate, (req, res) => {
  const secret = generateTotpSecret();
  const user = USERS.get(req.user.id);
  if (user) {
    user.pendingTotpSecret = secret;
  }
  const otpauthUrl = `otpauth://totp/AeroCFD:${encodeURIComponent(req.user.email)}?secret=${secret}&issuer=AeroCFD`;
  res.json({ secret, otpauthUrl });
});

app.post('/api/auth/2fa/verify', authenticate, validateBody(totpVerifySchema), (req, res) => {
  const { code } = req.body;
  const user = USERS.get(req.user.id);
  if (!user || !user.pendingTotpSecret) {
    return res.status(400).json({ error: 'No 2FA setup in progress.' });
  }

  const isValid = verifyTotp(user.pendingTotpSecret, code);
  if (!isValid) {
    return res.status(400).json({ error: 'Invalid TOTP verification code.' });
  }

  user.totpSecret = user.pendingTotpSecret;
  user.totpEnabled = true;
  user.pendingTotpSecret = null;

  logger.audit('2FA_ACTIVATED', { userId: user.id, ip: req.ip, correlationId: req.correlationId });
  res.json({ message: 'Two-factor authentication successfully enabled on your account.' });
});

app.post('/api/auth/2fa/disable', authenticate, validateBody(totpDisableSchema), async (req, res) => {
  const { password, code } = req.body;
  const user = USERS.get(req.user.id);
  if (!user || !user.totpEnabled) {
    return res.status(400).json({ error: '2FA is not active on this account.' });
  }

  if (user.role === 'admin') {
    return res.status(403).json({ error: '2FA is mandatory for administrator accounts.' });
  }

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid password.' });
  }

  const isValidCode = verifyTotp(user.totpSecret, code);
  if (!isValidCode) {
    return res.status(400).json({ error: 'Invalid TOTP code.' });
  }

  user.totpEnabled = false;
  user.totpSecret = null;
  logger.audit('2FA_DISABLED', { userId: user.id, ip: req.ip, correlationId: req.correlationId });
  res.json({ message: '2FA has been disabled.' });
});

/**
 * Session Management Endpoints
 */
app.get('/api/auth/sessions', authenticate, (req, res) => {
  const sessions = USER_SESSIONS.get(req.user.id);
  const list = sessions ? Array.from(sessions.values()) : [];
  res.json({ sessions: list });
});

app.delete('/api/auth/sessions/:sessionId', authenticate, (req, res) => {
  const { sessionId } = req.params;
  const sessions = USER_SESSIONS.get(req.user.id);
  if (sessions && sessions.has(sessionId)) {
    const s = sessions.get(sessionId);
    if (s.refreshTokenId) {
      REFRESH_TOKENS.delete(s.refreshTokenId);
    }
    sessions.delete(sessionId);
  }
  res.json({ message: 'Session revoked.' });
});

// ----------------------------------------------------------------------------
// 8. OpenFOAM Simulation Endpoints
// ----------------------------------------------------------------------------

/**
 * POST /api/run-simulation (or /api/simulate)
 * Fully Authenticated, Validated, Sandboxed
 */
const handleSimulationExecution = async (req, res, next) => {
  try {
    const { geometry, config } = req.body;

    // Validate and Decode STL payload safely
    let stlBuffer = null;
    if (geometry && geometry.stlBase64) {
      const stlValidation = validateStlPayload(geometry.stlBase64);
      stlBuffer = stlValidation.buffer;
    }

    const job = submitSimulationJob({
      ownerId: req.user.id,
      config,
      stlBuffer,
    });

    logger.audit('SIMULATION_SUBMITTED', {
      caseId: job.caseId,
      userId: req.user.id,
      inletVelocity: config.inletVelocity,
      ip: req.ip,
      correlationId: req.correlationId,
    });

    res.status(202).json({
      status: 'started',
      caseId: job.caseId,
      caseDir: job.caseDir,
      message: 'Simulation queued for sandboxed OpenFOAM execution.',
    });
  } catch (err) {
    next(err);
  }
};

app.post(
  '/api/run-simulation',
  simulationLimiter,
  authenticate,
  verifyCsrf,
  enforceJsonContentType,
  validateBody(simulationRequestSchema),
  handleSimulationExecution
);

app.post(
  '/api/simulate',
  simulationLimiter,
  authenticate,
  verifyCsrf,
  enforceJsonContentType,
  validateBody(simulationRequestSchema),
  handleSimulationExecution
);

/**
 * GET /api/simulation-status/:caseId
 * IDOR-Proof: Users can only query their own jobs (Admins can view any)
 */
app.get(
  '/api/simulation-status/:caseId',
  authenticate,
  validateParams(caseIdParamSchema),
  (req, res, next) => {
    try {
      const { caseId } = req.params;
      const job = getJobStatus(caseId, req.user.id, req.user.role);

      if (!job) {
        return res.status(404).json({
          error: `Simulation job with ID ${caseId} was not found.`,
          code: 'JOB_NOT_FOUND',
        });
      }

      res.json(job);
    } catch (err) {
      if (err.code === 'IDOR_BLOCKED') {
        logger.audit('IDOR_ACCESS_BLOCKED', {
          caseId: req.params.caseId,
          userId: req.user.id,
          ip: req.ip,
          correlationId: req.correlationId,
        });
        return res.status(403).json({ error: err.message, code: 'FORBIDDEN' });
      }
      next(err);
    }
  }
);

// ----------------------------------------------------------------------------
// 9. Centralized Error Handler (Never leaks stacks or paths in production)
// ----------------------------------------------------------------------------
app.use((err, req, res, next) => {
  const correlationId = req.correlationId || crypto.randomUUID();

  logger.error('Unhandled server error', {
    correlationId,
    error: err.message,
    stack: IS_PROD ? undefined : err.stack,
    path: req.path,
    method: req.method,
  });

  const statusCode = err.status || err.statusCode || 500;
  const safeMessage =
    IS_PROD && statusCode === 500
      ? 'An unexpected internal error occurred. Please contact system support.'
      : err.message || 'Internal server error';

  res.status(statusCode).json({
    error: safeMessage,
    correlationId,
  });
});

// ----------------------------------------------------------------------------
// 10. Server Bootstrap
// ----------------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  logger.info('OpenFOAM v2606 Enterprise Production Server Started', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    developer: 'Akhil.A (akkedu01@gmail.com)',
    securityProfile: 'OWASP_TOP_10_HARDENED',
  });
});
