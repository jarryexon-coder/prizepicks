// server.js - PRODUCTION WITH RAILWAY FIXES
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import mongoose from 'mongoose';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import Redis from 'ioredis';
import axios from 'axios';
import NodeCache from 'node-cache';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = process.env.PORT || 3002;
const HOST = process.env.HOST || '0.0.0.0';

// 🔧 FIX: Trust Railway's proxy headers
app.set('trust proxy', 1); // Trust first proxy

console.log('🚀 NBA Fantasy AI Backend - PRODUCTION WITH RAILWAY FIXES');
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`Trust proxy: ${app.get('trust proxy')}`);

// ====================
// REDIS CLIENT (Optional)
// ====================
let redisClient = null;
if (process.env.REDIS_URL) {
  try {
    redisClient = new Redis(process.env.REDIS_URL);
    redisClient.on('connect', () => console.log('✅ Redis connected'));
    redisClient.on('error', (err) => console.log('Redis error:', err.message));
  } catch (error) {
    console.log('⚠️  Redis connection failed:', error.message);
  }
}

// ====================
// CORS CONFIGURATION - UPDATED WITH VERCEL DOMAINS
// ====================
const allowedOrigins = [
  // Vercel production domain
  'https://sportsanalyticsgpt.com',
  'https://www.sportsanalyticsgpt.com',
  
  // Vercel deployment domains
  'https://nba-frontend-web.vercel.app',
  'https://nba-frontend-web-git-main-jarryexon-2517s-projects.vercel.app',
  
  // Railway domains
  'https://februaryfantasy-production.up.railway.app',
  'http://februaryfantasy-production.up.railway.app',
  'https://pleasing-determination-production.up.railway.app',
  'http://pleasing-determination-production.up.railway.app',
  
  // Local development
  'http://localhost:19006',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:3002',
  'http://localhost:8080',
  'http://localhost:5173', // Vite default port
  'http://127.0.0.1:3000',
  'http://127.0.0.1:3001',
  'http://127.0.0.1:3002',
  'http://127.0.0.1:5173',
  
  // Wildcard patterns for preview deployments
  /\.vercel\.app$/, // All Vercel deployments
  /\.railway\.app$/, // All Railway deployments
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or server-to-server)
    if (!origin) {
      console.log('🌐 No origin header - allowing request (likely server-to-server)');
      return callback(null, true);
    }
    
    console.log(`🔍 CORS checking origin: ${origin}`);
    
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        const match = origin === allowedOrigin;
        if (match) console.log(`✅ Origin matched exact: ${allowedOrigin}`);
        return match;
      }
      if (allowedOrigin instanceof RegExp) {
        const match = allowedOrigin.test(origin);
        if (match) console.log(`✅ Origin matched regex: ${allowedOrigin.source}`);
        return match;
      }
      return false;
    });
    
    if (isAllowed) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS blocked origin: ${origin}`);
      console.log('📋 Allowed origins:', allowedOrigins.map(o => typeof o === 'string' ? o : o.source));
      callback(new Error(`CORS policy: Origin ${origin} is not allowed`), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With', 
    'X-API-Key', 
    'Accept', 
    'Origin',
    'X-CSRF-Token',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ],
  exposedHeaders: ['Content-Range', 'X-Content-Range', 'X-Request-ID'],
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 204,
  preflightContinue: false
};

// Apply CORS middleware
app.use(cors(corsOptions));

// ====================
// ENHANCED PREFLIGHT HANDLER
// ====================
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  console.log(`🛬 Preflight request for: ${req.method} ${req.originalUrl}`);
  console.log(`   Origin: ${origin}`);
  console.log(`   Access-Control-Request-Method: ${req.headers['access-control-request-method']}`);
  console.log(`   Access-Control-Request-Headers: ${req.headers['access-control-request-headers']}`);
  
  // Check if origin is allowed
  const isOriginAllowed = !origin || allowedOrigins.some(allowedOrigin => {
    if (typeof allowedOrigin === 'string') return origin === allowedOrigin;
    if (allowedOrigin instanceof RegExp) return allowedOrigin.test(origin);
    return false;
  });
  
  if (isOriginAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-API-Key, Accept, Origin, X-CSRF-Token');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Access-Control-Expose-Headers', 'X-Request-ID');
    res.status(204).end();
  } else {
    console.warn(`❌ Preflight blocked for origin: ${origin}`);
    res.status(403).json({
      error: 'CORS preflight failed',
      message: `Origin ${origin} not allowed`,
      timestamp: new Date().toISOString()
    });
  }
});

// ====================
// SECURITY & PERFORMANCE
// ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdn.jsdelivr.net"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ====================
// MONITORING IMPROVEMENTS
// ====================
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url} from ${req.ip}`);
  next();
});

// ====================
// CACHE CONFIGURATION
// ====================
// Cache for 5 minutes (300 seconds). Check for stale data after 4 minutes.
const prizePicksCache = new NodeCache({ 
  stdTTL: 300,      // Time-To-Live: 5 minutes
  checkperiod: 60   // Cleanup interval: 1 minute
});

// ====================
// RATE LIMIT CONFIGURATION
// ====================
// Updated PrizePicks limiter - 15 requests per 15 minutes
const prizePicksLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Updated from 30 to 15 as you suggested
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful cached responses
  keyGenerator: (req) => {
    return req.ip; // Default: IP-based limiting
  },
  handler: (req, res) => {
    console.warn(`⚠️ Rate limit reached for ${req.ip} on ${req.url}`);
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many requests, please try again later.',
      retryAfter: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
    });
  }
});

// Fantasy Hub limiter
const fantasyHubLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.ip;
  },
  handler: (req, res) => {
    console.warn(`⚠️ Fantasy Hub rate limit reached for ${req.ip}`);
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many requests to Fantasy Hub, please try again later.'
    });
  }
});

// ====================
// ENHANCED HELPER FUNCTIONS FOR RAILWAY
// ====================

/**
 * Enhanced PrizePicks fetcher with better headers for Railway
 */
async function fetchLivePrizePicksProjections(leagueId = '7') {
  console.log(`🔄 [Live Fetch] Starting for league ${leagueId}`);
  
  try {
    // PHASE 1: Better headers for initial request
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Cache-Control': 'max-age=0',
      'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"macOS"'
    };
    
    console.log('   Establishing session with /leagues endpoint...');
    const leaguesResponse = await axios.get('https://api.prizepicks.com/leagues', {
      params: {
        'state_code': 'GA',
        'game_mode': 'prizepools'
      },
      headers: headers,
      timeout: 15000,
      // 🔧 IMPORTANT: Accept 4xx as valid response to handle gracefully
      validateStatus: function (status) {
        return status >= 200 && status < 500; // Accept 4xx as valid response
      }
    });
    
    if (leaguesResponse.status === 403 || leaguesResponse.status === 429) {
      throw new Error(`Blocked by PrizePicks: HTTP ${leaguesResponse.status}`);
    }
    
    const cookies = leaguesResponse.headers['set-cookie'] || [];
    const cookieHeader = cookies.map(c => c.split(';')[0]).join('; ');
    console.log(`   Obtained ${cookies.length} session cookies.`);
    
    // PHASE 2: Enhanced headers for projections request
    const projectionHeaders = {
      ...headers,
      'Accept': 'application/json, text/plain, */*',
      'Referer': 'https://app.prizepicks.com/',
      'Origin': 'https://app.prizepicks.com',
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'same-site',
      'Cookie': cookieHeader,
      'X-Requested-With': 'XMLHttpRequest'
    };
    
    console.log(`   Fetching projections for league ${leagueId}...`);
    const projectionsResponse = await axios.get('https://api.prizepicks.com/projections', {
      params: {
        'league_id': leagueId,
        'per_page': '50', // Reduced for less suspicion
        'single_stat': 'true',
        'state_code': 'GA',
        'game_mode': 'prizepools'
      },
      headers: projectionHeaders,
      timeout: 20000,
      validateStatus: function (status) {
        return status >= 200 && status < 500;
      }
    });
    
    if (projectionsResponse.status === 403 || projectionsResponse.status === 429) {
      throw new Error(`Projections blocked: HTTP ${projectionsResponse.status}`);
    }
    
    const apiData = projectionsResponse.data;
    console.log(`   ✅ Success! Received ${apiData.data?.length || 0} raw projections.`);
    return apiData;
    
  } catch (error) {
    console.error(`   ❌ Live fetch failed: ${error.message}`);
    
    // Try alternative state code if GA is blocked
    if (error.message.includes('403') || error.message.includes('429')) {
      console.log('   ⚠️ Trying alternative state code (NY)...');
      return await tryAlternativeStateCode(leagueId);
    }
    
    throw error;
  }
}

async function tryAlternativeStateCode(leagueId) {
  // Try different state codes
  const stateCodes = ['NY', 'IL', 'NJ', 'PA', 'CA'];
  
  for (const state of stateCodes) {
    try {
      console.log(`   Trying state code: ${state}`);
      
      const leaguesResponse = await axios.get('https://api.prizepicks.com/leagues', {
        params: { 'state_code': state, 'game_mode': 'prizepools' },
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Accept': 'application/json, text/plain, */*'
        },
        timeout: 10000
      });
      
      const cookies = leaguesResponse.headers['set-cookie'] || [];
      const cookieHeader = cookies.map(c => c.split(';')[0]).join('; ');
      
      const projectionsResponse = await axios.get('https://api.prizepicks.com/projections', {
        params: {
          'league_id': leagueId,
          'per_page': '30',
          'single_stat': 'true',
          'state_code': state,
          'game_mode': 'prizepools'
        },
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
          'Referer': 'https://app.prizepicks.com/',
          'Cookie': cookieHeader,
          'X-Requested-With': 'XMLHttpRequest'
        },
        timeout: 15000
      });
      
      console.log(`   ✅ Success with state ${state}!`);
      return projectionsResponse.data;
      
    } catch (stateError) {
      console.log(`   State ${state} failed: ${stateError.message}`);
      continue;
    }
  }
  
  throw new Error('All state codes failed');
}

/**
 * Generates realistic, dynamic fallback data when the live API fails.
 */
function generateIntelligentFallbackData(sport = 'NBA') {
  console.log(`🛠️ [Fallback] Generating intelligent data for ${sport}`);
  const players = {
    'NBA': [
      { name: 'Luka Doncic', team: 'DAL', basePoints: 32.5, baseReb: 8.5, baseAst: 9.2 },
      { name: 'Jayson Tatum', team: 'BOS', basePoints: 27.8, baseReb: 8.1, baseAst: 4.8 },
      { name: 'Nikola Jokic', team: 'DEN', basePoints: 25.3, baseReb: 11.8, baseAst: 9.1 },
      { name: 'Shai Gilgeous-Alexander', team: 'OKC', basePoints: 31.2, baseReb: 5.5, baseAst: 6.4 },
      { name: 'Giannis Antetokounmpo', team: 'MIL', basePoints: 30.8, baseReb: 11.5, baseAst: 6.2 }
    ],
    'NFL': [
      { name: 'Patrick Mahomes', team: 'KC', basePassYards: 295, baseRushYards: 15, baseTDs: 2.3 },
      { name: 'Christian McCaffrey', team: 'SF', baseRushYards: 95, baseRecYards: 45, baseTDs: 1.2 },
      { name: 'Justin Jefferson', team: 'MIN', baseRecYards: 105, baseRec: 7.5, baseTDs: 0.8 }
    ]
  };

  const playerPool = players[sport] || players['NBA'];
  const selections = [];

  playerPool.forEach((player, idx) => {
    // Create variance to simulate different lines
    const variance = 0.9 + (Math.random() * 0.2); // 0.9 to 1.1
    const line = Math.round((player.basePoints * variance) * 10) / 10;
    const projection = line + (Math.random() * 3) + 0.5; // Projection is usually higher

    selections.push({
      id: `fallback-${sport}-${idx}`,
      player: player.name,
      team: player.team,
      sport: sport,
      stat: 'Points',
      line: line,
      type: 'Over',
      projection: parseFloat(projection.toFixed(1)),
      confidence: ['medium', 'high'][Math.floor(Math.random() * 2)],
      odds: `-${110 + Math.floor(Math.random() * 40)}`,
      timestamp: new Date().toISOString(),
      analysis: `Fallback data | ${player.name} season avg: ${player.basePoints}`,
      status: 'pending',
      source: 'intelligent-fallback'
    });
  });
  return selections;
}

/**
 * Transforms raw PrizePicks API data into your frontend's expected format.
 */
function transformPrizePicksData(apiData, sport) {
  console.log(`   Transforming raw API data...`);
  const playerMap = {};
  const teamMap = {};

  // Build lookup dictionaries from the 'included' array
  if (apiData.included) {
    apiData.included.forEach(item => {
      if (item.type === 'new_player') playerMap[item.id] = item.attributes?.name;
      if (item.type === 'team') teamMap[item.id] = item.attributes?.name;
    });
  }

  const selections = [];
  const seenKeys = new Set();

  apiData.data?.forEach(proj => {
    try {
      const attrs = proj.attributes || {};
      if (attrs.event_type === 'team') return; // Skip team props

      const playerId = proj.relationships?.new_player?.data?.id;
      const playerName = playerMap[playerId];
      if (!playerName) return; // Skip if we can't find the player

      const statDisplay = attrs.stat_display_name || 'Points';
      const uniqueKey = `${playerId}-${statDisplay}`;
      if (seenKeys.has(uniqueKey)) return; // Deduplicate
      seenKeys.add(uniqueKey);

      const teamId = proj.relationships?.team?.data?.id;
      const lineScore = parseFloat(attrs.line_score) || 0;

      selections.push({
        id: proj.id,
        player: playerName,
        team: teamMap[teamId] || '',
        sport: sport,
        stat: statDisplay,
        line: lineScore,
        type: 'Over',
        projection: lineScore,
        confidence: (attrs.trending_count > 100000) ? 'high' : 'medium',
        odds: '-110',
        timestamp: attrs.updated_at || new Date().toISOString(),
        analysis: `${playerName} ${statDisplay} vs ${teamMap[teamId] || 'Opponent'}`,
        status: 'pending',
        source: 'prizepicks-live'
      });
    } catch (err) {
      console.log(`   Skipping a projection due to error: ${err.message}`);
    }
  });
  console.log(`   ✅ Transformed into ${selections.length} clean selections.`);
  return selections;
}

// ====================
// REQUEST LOGGING
// ====================
app.use((req, res, next) => {
  const start = Date.now();
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  
  console.log(`[${requestId}] ${req.method} ${req.originalUrl}`, {
    origin: req.headers.origin || 'no-origin',
    'user-agent': req.headers['user-agent']?.substring(0, 50),
    ip: req.ip,
    xForwardedFor: req.headers['x-forwarded-for']
  });
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', requestId);
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${requestId}] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  
  next();
});

// ====================
// SWAGGER DOCUMENTATION
// ====================
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'NBA Fantasy AI API',
      version: '2.0.0',
      description: 'NBA Fantasy AI Backend API Documentation',
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: 'https://pleasing-determination-production.up.railway.app',
        description: 'Production server',
      },
      {
        url: 'http://localhost:3002',
        description: 'Local development server',
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: ['./routes/*.js'],
};

try {
  const swaggerSpec = swaggerJsdoc(swaggerOptions);
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: "NBA Fantasy AI API Docs"
  }));
  
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });
  
  console.log('✅ Swagger documentation loaded');
} catch (error) {
  console.log('⚠️  Swagger setup failed:', error.message);
}

// ====================
// MIDDLEWARE TO CONVERT OBJECT RESPONSES TO ARRAYS
// ====================
app.use((req, res, next) => {
  console.log(`🛠️ Request to: ${req.path}`);
  
  const originalJson = res.json;
  
  res.json = function(data) {
    console.log(`🛠️ Response for ${req.path}:`, data?.success ? 'Success' : 'Failed');
    
    // Only process successful responses
    if (data && data.success === true) {
      console.log(`🛠️ Processing ${req.path}...`);
      
      // NFL Standings
      if (req.path.includes('/nfl/standings')) {
        console.log(`🛠️ Found NFL standings endpoint`);
        if (data.standings && typeof data.standings === 'object' && !Array.isArray(data.standings)) {
          console.log(`🛠️ Converting NFL standings object to array...`);
          const allTeams = [];
          
          // Check for the nested structure
          if (data.standings.afc && Array.isArray(data.standings.afc)) {
            console.log(`🛠️ Found AFC divisions: ${data.standings.afc.length}`);
            data.standings.afc.forEach((division, i) => {
              if (division.teams && Array.isArray(division.teams)) {
                console.log(`🛠️ Division ${i}: ${division.teams.length} teams`);
                allTeams.push(...division.teams.map(team => ({
                  ...team,
                  conference: 'AFC',
                  division: division.division
                })));
              }
            });
          }
          
          if (data.standings.nfc && Array.isArray(data.standings.nfc)) {
            console.log(`🛠️ Found NFC divisions: ${data.standings.nfc.length}`);
            data.standings.nfc.forEach((division, i) => {
              if (division.teams && Array.isArray(division.teams)) {
                console.log(`🛠️ Division ${i}: ${division.teams.length} teams`);
                allTeams.push(...division.teams.map(team => ({
                  ...team,
                  conference: 'NFC',
                  division: division.division
                })));
              }
            });
          }
          
          data.standings = allTeams;
          console.log(`✅ Converted NFL standings: ${allTeams.length} total teams`);
        } else {
          console.log(`ℹ️ NFL standings already array or not object`);
        }
      }
      
      // NHL Standings (similar pattern)
      if (req.path.includes('/nhl/standings')) {
        console.log(`🛠️ Found NHL standings endpoint`);
        if (data.standings && typeof data.standings === 'object' && !Array.isArray(data.standings)) {
          console.log(`🛠️ Converting NHL standings object to array...`);
          const allTeams = [];
          
          if (data.standings.eastern && Array.isArray(data.standings.eastern)) {
            data.standings.eastern.forEach(division => {
              if (division.teams && Array.isArray(division.teams)) {
                allTeams.push(...division.teams.map(team => ({
                  ...team,
                  conference: 'Eastern',
                  division: division.division
                })));
              }
            });
          }
          
          if (data.standings.western && Array.isArray(data.standings.western)) {
            data.standings.western.forEach(division => {
              if (division.teams && Array.isArray(division.teams)) {
                allTeams.push(...division.teams.map(team => ({
                  ...team,
                  conference: 'Western',
                  division: division.division
                })));
              }
            });
          }
          
          data.standings = allTeams;
          console.log(`✅ Converted NHL standings: ${allTeams.length} total teams`);
        }
      }
      
      // PrizePicks Analytics
      if (req.path.includes('/prizepicks/analytics')) {
        console.log(`🛠️ Found PrizePicks analytics endpoint`);
        if (data.analytics && typeof data.analytics === 'object' && !Array.isArray(data.analytics)) {
          console.log(`🛠️ Converting PrizePicks analytics object to array...`);
          const allItems = [];
          
          if (data.analytics.bySport && Array.isArray(data.analytics.bySport)) {
            allItems.push(...data.analytics.bySport.map(item => ({
              type: 'sport_performance',
              ...item
            })));
          }
          
          if (data.analytics.topPerformers && Array.isArray(data.analytics.topPerformers)) {
            allItems.push(...data.analytics.topPerformers.map(item => ({
              type: 'top_performer',
              ...item
            })));
          }
          
          if (data.analytics.byPickType && Array.isArray(data.analytics.byPickType)) {
            allItems.push(...data.analytics.byPickType.map(item => ({
              type: 'pick_type',
              ...item
            })));
          }
          
          data.analytics = allItems;
          console.log(`✅ Converted PrizePicks analytics: ${allItems.length} total items`);
        }
      }
    }
    
    // Call the original json method with modified data
    return originalJson.call(this, data);
  };
  
  next();
});

console.log('🔧 Response converter middleware loaded - BEFORE all routes');

// ====================
// BASIC ENDPOINTS
// ====================
app.get('/', (req, res) => {
  res.json({
    service: 'NBA Fantasy AI Backend',
    version: '2.0.0',
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    documentation: '/api-docs',
    health: '/health',
    api: '/api',
    cors: {
      enabled: true,
      allowedOrigins: allowedOrigins.map(o => typeof o === 'string' ? o : o.source)
    },
    proxy: {
      trusted: app.get('trust proxy'),
      ip: req.ip,
      xForwardedFor: req.headers['x-forwarded-for']
    }
  });
});

app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: redisClient?.status || 'disabled',
    mongodb: 'disconnected',
    cors: {
      origin: req.headers.origin || 'none',
      allowed: true
    },
    proxy: {
      trusted: app.get('trust proxy'),
      ip: req.ip
    }
  };
  
  // Check MongoDB connection
  if (mongoose.connection.readyState === 1) {
    health.mongodb = 'connected';
  }
  
  res.json(health);
});

app.get('/railway-health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    service: 'NBA Fantasy API',
    version: '2.0.0',
    cors: {
      clientOrigin: req.headers.origin || 'unknown',
      allowed: true
    },
    proxy: {
      trusted: app.get('trust proxy'),
      ip: req.ip
    }
  });
});

// ====================
// API GATEWAY
// ====================
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'NBA Fantasy AI API Gateway',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    client: {
      origin: req.headers.origin || 'unknown',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    },
    documentation: {
      swaggerUI: '/api-docs',
      swaggerJSON: '/api-docs.json'
    },
    coreEndpoints: [
      { path: '/api/nba', description: 'NBA data and statistics' },
      { path: '/api/auth/health', description: 'Authentication service health' },
      { path: '/api/admin/health', description: 'Administration service health' },
      { path: '/api/user', description: 'User management' },
      { path: '/api/games', description: 'Game schedules and results' },
      { path: '/api/news', description: 'Sports news and updates' },
      { path: '/api/sportsbooks', description: 'Sports betting data' },
      { path: '/api/prizepicks/selections', description: 'PrizePicks selections with caching' },
      { path: '/api/fantasyhub/players', description: 'Fantasy Hub enriched player data' }
    ]
  });
});

app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'API test endpoint - All systems operational',
    timestamp: new Date().toISOString(),
    status: 'operational',
    clientOrigin: req.headers.origin || 'unknown',
    features: {
      cors: 'enabled',
      security: 'enabled',
      compression: 'enabled',
      documentation: 'available',
      redis: redisClient ? 'connected' : 'disabled',
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      proxy: app.get('trust proxy') ? 'enabled' : 'disabled'
    }
  });
});

// ====================
// MAIN PRIZEPICKS ENDPOINT WITH CACHING AND RATE LIMITING
// ====================

app.get('/api/prizepicks/selections', prizePicksLimiter, async (req, res, next) => {
  const sport = (req.query.sport || 'nba').toUpperCase();
  const leagueMap = { 'NBA': '7', 'NFL': '1', 'MLB': '3', 'NHL': '4' };
  const leagueId = leagueMap[sport] || '7';
  const cacheKey = `prizepicks_${sport}`;

  console.log(`\n🎯 [Request] /prizepicks/selections for ${sport} (League: ${leagueId}) from ${req.ip}`);

  // ----- CHECK CACHE FIRST -----
  const cached = prizePicksCache.get(cacheKey);
  if (cached) {
    req.cacheHit = true; // Mark as cache hit for rate limiter
    console.log(`✅ Serving fresh data from cache.`);
    return res.json({ ...cached, servedFrom: 'cache', cacheHit: true });
  }
  
  req.cacheHit = false;
  next();
}, async (req, res) => {
  const sport = (req.query.sport || 'nba').toUpperCase();
  const leagueMap = { 'NBA': '7', 'NFL': '1', 'MLB': '3', 'NHL': '4' };
  const leagueId = leagueMap[sport] || '7';
  const cacheKey = `prizepicks_${sport}`;

  // ----- LIVE FETCH & FALLBACK LOGIC -----
  let finalSelections = [];
  let dataSource = '';

  try {
    // ATTEMPT 1: Enhanced PrizePicks API
    console.log(`   Cache miss. Attempting live fetch...`);
    const liveData = await fetchLivePrizePicksProjections(leagueId);
    finalSelections = transformPrizePicksData(liveData, sport);
    dataSource = 'prizepicks-live';
    console.log(`   ✅ Live fetch successful.`);

  } catch (liveError) {
    console.error(`   ❌ Live fetch failed: ${liveError.message}`);
    
    // ATTEMPT 2: Intelligent Fallback
    console.log(`   Activating intelligent fallback...`);
    finalSelections = generateIntelligentFallbackData(sport);
    dataSource = 'intelligent-fallback';
    
    // Store fallback in cache with a SHORTER TTL (2 minutes)
    prizePicksCache.set(cacheKey, {
      success: true,
      message: `PrizePicks ${sport} Selections (Fallback Active - API Blocked)`,
      selections: finalSelections,
      count: finalSelections.length,
      timestamp: new Date().toISOString(),
      source: dataSource,
      note: 'PrizePicks API may be blocking Railway IPs. Using fallback data.'
    }, 120); // 2 minute TTL for fallback data
    console.log(`   ✅ Fallback generated and cached briefly.`);
  }

  // ----- CACHE & RESPOND -----
  // Only cache successful live data with the standard 5-minute TTL
  if (dataSource === 'prizepicks-live') {
    const responsePayload = {
      success: true,
      message: `PrizePicks ${sport} Selections`,
      selections: finalSelections,
      count: finalSelections.length,
      timestamp: new Date().toISOString(),
      source: dataSource
    };
    prizePicksCache.set(cacheKey, responsePayload); // Uses standard 5-min TTL
    console.log(`   ✅ Live response cached for 5 minutes.`);
  }

  // Send the final response
  res.json({
    success: true,
    message: `PrizePicks ${sport} Selections`,
    selections: finalSelections,
    count: finalSelections.length,
    timestamp: new Date().toISOString(),
    source: dataSource,
    servedFrom: 'live-or-fallback',
    note: dataSource === 'intelligent-fallback' ? 'Using fallback data due to API restrictions' : 'Live data from PrizePicks'
  });
});

// ====================
// FANTASY HUB ENDPOINT WITH ENRICHED DATA
// ====================

app.get('/api/fantasyhub/players', fantasyHubLimiter, async (req, res) => {
  console.log('\n🏈 [FantasyHub] /players endpoint called');
  
  try {
    const { 
      date = 'today',
      detailed = 'false'
    } = req.query;
    
    // ----- PHASE 1: Get Core Player Projections (PrizePicks) -----
    console.log('1. Fetching player projections from PrizePicks...');
    const prizePicksData = await fetchPrizePicksForFantasy(date);
    
    if (!prizePicksData || prizePicksData.length === 0) {
      throw new Error('No player projections available');
    }
    
    // ----- PHASE 2: Enrich with Player Context (RapidAPI) -----
    console.log('2. Enriching with player context from RapidAPI...');
    const playersWithContext = await enrichWithPlayerContext(prizePicksData);
    
    // ----- PHASE 3: Add Historical Stats (BallDontLie) -----
    console.log('3. Adding historical stats from BallDontLie...');
    const playersWithStats = await enrichWithHistoricalStats(playersWithContext);
    
    // ----- PHASE 4: Calculate Fantasy Value Scores -----
    console.log('4. Calculating fantasy value scores...');
    const finalPlayers = calculateFantasyScores(playersWithStats);
    
    // ----- PHASE 5: Format and Return -----
    console.log(`✅ Processed ${finalPlayers.length} players for Fantasy Hub`);
    
    res.json({
      success: true,
      message: `Fantasy Hub Analysis for ${date}`,
      players: detailed === 'true' ? finalPlayers : finalPlayers.slice(0, 20),
      total_players: finalPlayers.length,
      date: date,
      timestamp: new Date().toISOString(),
      data_sources: ['prizepicks', 'rapidapi-player-context', 'balldontlie-stats'],
      note: 'Projections from PrizePicks, enriched with player context and historical stats'
    });
    
  } catch (error) {
    console.error('❌ Fantasy Hub error:', error.message);
    
    // Intelligent fallback
    res.json({
      success: true,
      message: 'Fantasy Hub Analysis (Fallback Mode)',
      players: generateIntelligentFantasyFallback(),
      total_players: 15,
      timestamp: new Date().toISOString(),
      data_sources: ['fallback'],
      note: 'Using fallback data: ' + error.message
    });
  }
});

// ====================
// FANTASY HUB HELPER FUNCTIONS (UPDATED)
// ====================

/**
 * 1. Fetch PrizePicks data formatted for Fantasy Hub
 */
async function fetchPrizePicksForFantasy(dateParam) {
  try {
    // Try the enhanced fetcher first
    const prizePicksData = await fetchLivePrizePicksProjections('7');
    
    if (!prizePicksData || !prizePicksData.data || prizePicksData.data.length === 0) {
      throw new Error('No data returned from PrizePicks');
    }
    
    // Transform to Fantasy Hub format
    const playerMap = {};
    if (prizePicksData.included) {
      prizePicksData.included.forEach(item => {
        if (item.type === 'new_player') {
          playerMap[item.id] = {
            name: item.attributes?.name || 'Unknown',
            team: item.attributes?.team || ''
          };
        }
      });
    }
    
    const fantasyPlayers = [];
    const seenPlayers = new Set();
    
    if (prizePicksData.data) {
      prizePicksData.data.forEach(proj => {
        try {
          const attrs = proj.attributes || {};
          if (attrs.event_type === 'team') return;
          
          const playerId = proj.relationships?.new_player?.data?.id;
          const playerInfo = playerMap[playerId];
          if (!playerInfo || seenPlayers.has(playerId)) return;
          
          seenPlayers.add(playerId);
          
          fantasyPlayers.push({
            player_id: `pp-${playerId}`,
            name: playerInfo.name,
            team: playerInfo.team,
            position: '', // Will fill from RapidAPI
            projection: {
              stat_type: attrs.stat_display_name || attrs.stat_type,
              line: parseFloat(attrs.line_score) || 0,
              confidence: attrs.trending_count > 100000 ? 'high' : 'medium',
              updated: attrs.updated_at
            },
            source: 'prizepicks'
          });
        } catch (e) {
          console.log('Skipping projection:', e.message);
        }
      });
    }
    
    return fantasyPlayers;
    
  } catch (error) {
    console.error('PrizePicks fetch failed, trying alternative approach...', error.message);
    
    // Alternative: Use the NBA Player Props API for player names at least
    try {
      return await getPlayersFromRapidAPI();
    } catch (rapidError) {
      console.error('All APIs failed:', rapidError.message);
      return []; // Return empty array, Fantasy Hub will use fallback
    }
  }
}

async function getPlayersFromRapidAPI() {
  const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY_PLAYER_PROPS;
  
  if (!RAPIDAPI_KEY) {
    throw new Error('RapidAPI key not configured');
  }
  
  const response = await axios.get(
    'https://nba-player-props-odds.p.rapidapi.com/get-events-for-date',
    {
      headers: {
        'x-rapidapi-host': 'nba-player-props-odds.p.rapidapi.com',
        'x-rapidapi-key': RAPIDAPI_KEY
      },
      timeout: 8000
    }
  );
  
  // Extract players from events (simplified)
  const players = [];
  const events = response.data || [];
  
  events.forEach(event => {
    // Add home team players (simplified)
    if (event.teams?.home?.name) {
      players.push({
        name: `${event.teams?.home?.city} ${event.teams?.home?.name} Player`,
        team: event.teams?.home?.abbreviation || 'UNK',
        position: 'Unknown',
        projection: { 
          stat_type: 'Points', 
          line: Math.random() * 30 + 10, 
          confidence: 'medium',
          updated: new Date().toISOString()
        },
        source: 'rapidapi-fallback'
      });
    }
    
    // Add away team players (simplified)
    if (event.teams?.away?.name) {
      players.push({
        name: `${event.teams?.away?.city} ${event.teams?.away?.name} Player`,
        team: event.teams?.away?.abbreviation || 'UNK',
        position: 'Unknown',
        projection: { 
          stat_type: 'Points', 
          line: Math.random() * 30 + 10, 
          confidence: 'medium',
          updated: new Date().toISOString()
        },
        source: 'rapidapi-fallback'
      });
    }
  });
  
  return players.slice(0, 10); // Limit to 10 players
}

/**
 * 2. Enrich with player context from RapidAPI
 */
async function enrichWithPlayerContext(players) {
  const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY_PLAYER_PROPS || 'cdd1cfc95bmsh3dea79dcd1be496p167ea1jsnb355ed1075ec';
  
  try {
    // Get today's events to match players
    const eventsResponse = await axios.get(
      'https://nba-player-props-odds.p.rapidapi.com/get-events-for-date',
      {
        headers: {
          'x-rapidapi-host': 'nba-player-props-odds.p.rapidapi.com',
          'x-rapidapi-key': RAPIDAPI_KEY
        },
        timeout: 8000
      }
    );
    
    const events = eventsResponse.data || [];
    
    // For each player, try to find matching context
    return players.map(player => {
      // Simple matching logic (in practice, use more robust matching)
      const matchingEvent = events.find(event => 
        event.teams?.home?.abbreviation === player.team || 
        event.teams?.away?.abbreviation === player.team
      );
      
      // Get player props context for this player (if available)
      const playerContext = {
        matchup: matchingEvent ? 
          `${matchingEvent.teams?.away?.name} @ ${matchingEvent.teams?.home?.name}` : 
          'No matchup data',
        game_time: matchingEvent?.Date,
        position: 'Unknown' // Default
      };
      
      return {
        ...player,
        context: playerContext,
        // Note: We can't get actual odds from this API (books array is empty)
      };
    });
    
  } catch (error) {
    console.log('RapidAPI context enrichment failed:', error.message);
    return players; // Return players unchanged if enrichment fails
  }
}

/**
 * 3. Add historical stats from BallDontLie
 */
async function enrichWithHistoricalStats(players) {
  const BALLDONTLIE_KEY = process.env.BALLDONTLIE_API_KEY;
  
  if (!BALLDONTLIE_KEY) {
    console.log('BallDontLie API key not configured, skipping stats enrichment');
    return players.map(p => ({ ...p, historical_stats: null }));
  }
  
  console.log(`   Enriching ${players.length} players with historical stats...`);
  
  const enrichedPlayers = [];
  
  // Process in smaller batches to avoid rate limits
  for (let i = 0; i < Math.min(players.length, 10); i++) { // Limit to 10 players
    const player = players[i];
    
    try {
      // Search for player by name
      const searchResponse = await axios.get('https://api.balldontlie.io/v1/players', {
        headers: { 'Authorization': BALLDONTLIE_KEY },
        params: { 'search': player.name.split(' ')[0] }, // First name
        timeout: 5000
      });
      
      const ballDontLiePlayers = searchResponse.data.data || [];
      if (ballDontLiePlayers.length > 0) {
        const matchedPlayer = ballDontLiePlayers[0];
        
        // Get season averages
        const statsResponse = await axios.get('https://api.balldontlie.io/v1/season_averages', {
          headers: { 'Authorization': BALLDONTLIE_KEY },
          params: { 'player_ids[]': matchedPlayer.id, 'season': 2024 },
          timeout: 5000
        });
        
        const seasonStats = statsResponse.data.data?.[0] || {};
        
        enrichedPlayers.push({
          ...player,
          historical_stats: {
            player_id: matchedPlayer.id,
            position: matchedPlayer.position || player.context?.position || 'Unknown',
            height: matchedPlayer.height,
            weight: matchedPlayer.weight,
            season_averages: {
              points: seasonStats.pts || 0,
              rebounds: seasonStats.reb || 0,
              assists: seasonStats.ast || 0,
              steals: seasonStats.stl || 0,
              blocks: seasonStats.blk || 0,
              field_goal_pct: seasonStats.fg_pct || 0,
              games_played: seasonStats.games_played || 0
            }
          }
        });
      } else {
        enrichedPlayers.push({ ...player, historical_stats: null });
      }
      
      // Small delay to respect rate limits
      await new Promise(resolve => setTimeout(resolve, 300));
      
    } catch (error) {
      console.log(`   Failed to enrich ${player.name}:`, error.message);
      enrichedPlayers.push({ ...player, historical_stats: null });
    }
  }
  
  // Add remaining players without enrichment
  if (players.length > 10) {
    players.slice(10).forEach(p => {
      enrichedPlayers.push({ ...p, historical_stats: null });
    });
  }
  
  return enrichedPlayers;
}

/**
 * 4. Calculate fantasy value scores
 */
function calculateFantasyScores(players) {
  return players.map(player => {
    const projection = player.projection?.line || 0;
    const seasonAvg = player.historical_stats?.season_averages?.points || 0;
    
    // Simple fantasy score calculation (adjust based on your league rules)
    let fantasyScore = 50; // Base score
    
    if (projection > 0 && seasonAvg > 0) {
      // Higher projection than season average = positive indicator
      const projectionRatio = projection / seasonAvg;
      fantasyScore += Math.min(20, (projectionRatio - 1) * 30);
    }
    
    // Add position bonus
    const position = player.historical_stats?.position || '';
    if (position.includes('C') || position.includes('F')) {
      fantasyScore += 5; // Big men get rebound/block potential bonus
    }
    
    // Add confidence bonus from PrizePicks
    if (player.projection?.confidence === 'high') {
      fantasyScore += 10;
    }
    
    return {
      ...player,
      fantasy_score: Math.round(fantasyScore),
      recommendation: fantasyScore >= 70 ? 'Strong Play' : 
                     fantasyScore >= 55 ? 'Solid Option' : 
                     fantasyScore >= 40 ? 'Consider' : 'Risky Play'
    };
  }).sort((a, b) => b.fantasy_score - a.fantasy_score); // Sort by fantasy score
}

/**
 * Fallback data generator
 */
function generateIntelligentFantasyFallback() {
  console.log('🛠️ [Fantasy Fallback] Generating intelligent fallback data');
  
  const players = [
    {
      player_id: 'fallback-1',
      name: 'Luka Doncic',
      team: 'DAL',
      position: 'PG',
      projection: {
        stat_type: 'Points',
        line: 32.5,
        confidence: 'high',
        updated: new Date().toISOString()
      },
      context: {
        matchup: 'DAL @ GSW',
        game_time: new Date(Date.now() + 3600000).toISOString(),
        position: 'PG'
      },
      historical_stats: {
        player_id: 123,
        position: 'PG',
        height: '6-7',
        weight: '230',
        season_averages: {
          points: 33.1,
          rebounds: 8.6,
          assists: 9.4,
          steals: 1.4,
          blocks: 0.6,
          field_goal_pct: 48.7,
          games_played: 45
        }
      },
      fantasy_score: 85,
      recommendation: 'Strong Play',
      source: 'fallback'
    },
    {
      player_id: 'fallback-2',
      name: 'Nikola Jokic',
      team: 'DEN',
      position: 'C',
      projection: {
        stat_type: 'Points+Rebounds+Assists',
        line: 42.5,
        confidence: 'high',
        updated: new Date().toISOString()
      },
      context: {
        matchup: 'DEN @ PHX',
        game_time: new Date(Date.now() + 7200000).toISOString(),
        position: 'C'
      },
      historical_stats: {
        player_id: 456,
        position: 'C',
        height: '6-11',
        weight: '284',
        season_averages: {
          points: 25.8,
          rebounds: 12.1,
          assists: 9.2,
          steals: 1.2,
          blocks: 0.9,
          field_goal_pct: 58.3,
          games_played: 48
        }
      },
      fantasy_score: 88,
      recommendation: 'Strong Play',
      source: 'fallback'
    },
    {
      player_id: 'fallback-3',
      name: 'Shai Gilgeous-Alexander',
      team: 'OKC',
      position: 'SG',
      projection: {
        stat_type: 'Points',
        line: 31.0,
        confidence: 'medium',
        updated: new Date().toISOString()
      },
      context: {
        matchup: 'OKC @ LAL',
        game_time: new Date(Date.now() + 10800000).toISOString(),
        position: 'SG'
      },
      historical_stats: {
        player_id: 789,
        position: 'SG',
        height: '6-6',
        weight: '195',
        season_averages: {
          points: 31.8,
          rebounds: 5.6,
          assists: 6.4,
          steals: 2.2,
          blocks: 0.9,
          field_goal_pct: 54.8,
          games_played: 46
        }
      },
      fantasy_score: 82,
      recommendation: 'Strong Play',
      source: 'fallback'
    }
  ];
  
  return players;
}

// ====================
// EXISTING ENDPOINTS (KEEPING THEM ALL - shortened for brevity)
// ====================

// NBA API
app.get('/api/nba', (req, res) => {
  res.json({
    success: true,
    message: 'NBA API',
    timestamp: new Date().toISOString(),
    clientOrigin: req.headers.origin || 'unknown',
    endpoints: [
      { path: '/games', method: 'GET', description: 'Get NBA games' },
      { path: '/teams', method: 'GET', description: 'Get NBA teams' },
      { path: '/stats', method: 'GET', description: 'Get NBA statistics' },
      { path: '/scores/live', method: 'GET', description: 'Get live scores' }
    ]
  });
});

app.get('/api/nba/games', (req, res) => {
  console.log('🏀 /api/nba/games endpoint called');
  
  const games = [
    {
      id: 'nba-1',
      awayTeam: 'Los Angeles Lakers',
      homeTeam: 'Golden State Warriors',
      awayScore: 112,
      homeScore: 108,
      status: 'final',
      quarter: '4th',
      timeRemaining: '0:00',
      arena: 'Chase Center',
      broadcast: 'TNT',
      date: '2026-02-02T22:30:00Z',
      spread: 'GSW -3.5',
      overUnder: 235.5,
      attendance: 18064
    },
    {
      id: 'nba-2',
      awayTeam: 'Boston Celtics',
      homeTeam: 'Miami Heat',
      awayScore: 105,
      homeScore: 98,
      status: 'final',
      quarter: '4th',
      timeRemaining: '0:00',
      arena: 'FTX Arena',
      broadcast: 'ESPN',
      date: '2026-02-02T20:00:00Z',
      spread: 'BOS -4.5',
      overUnder: 218.5,
      attendance: 19600
    }
  ];
  
  res.json({
    success: true,
    message: 'NBA games',
    timestamp: new Date().toISOString(),
    games: games,
    count: games.length,
    season: '2025-2026',
    week: 'Regular Season Week 18'
  });
});

// ... (Keep all your existing endpoints - they remain unchanged)

// ====================
// TEST ENDPOINTS
// ====================
app.get('/api/cors-test', (req, res) => {
  res.json({
    success: true,
    message: 'CORS Test Endpoint',
    timestamp: new Date().toISOString(),
    clientInfo: {
      origin: req.headers.origin || 'no-origin',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      method: req.method,
      xForwardedFor: req.headers['x-forwarded-for']
    },
    cors: {
      allowedOrigins: allowedOrigins.map(o => typeof o === 'string' ? o : o.source),
      currentOriginAllowed: true
    },
    proxy: {
      trusted: app.get('trust proxy'),
      realIp: req.ip
    }
  });
});

app.get('/api/frontend-test', (req, res) => {
  res.json({
    success: true,
    message: 'Frontend Connection Test Successful!',
    timestamp: new Date().toISOString(),
    data: {
      service: 'NBA Fantasy AI Backend',
      version: '2.0.0',
      status: 'connected',
      origin: req.headers.origin || 'unknown',
      connection: 'CORS enabled and working',
      proxy: 'Trust proxy enabled for Railway',
      sampleData: {
        games: 5,
        sports: ['NBA', 'NFL', 'NHL'],
        liveGames: 3
      }
    }
  });
});

// ====================
// CATCH-ALL FOR /api/* ROUTES
// ====================
app.get('/api/*', (req, res) => {
  const path = req.originalUrl;
  
  console.log(`🔍 Catch-all API route: ${path}`);
  
  res.json({
    success: true,
    message: 'API endpoint available',
    path: path,
    timestamp: new Date().toISOString(),
    note: 'This is a valid API endpoint. Check documentation for specific endpoints.',
    documentation: '/api-docs',
    availableEndpoints: [
      '/api/nba',
      '/api/nba/games',
      '/api/nfl/games',
      '/api/nfl/stats',
      '/api/nfl/standings',
      '/api/nhl/games',
      '/api/nhl/players',
      '/api/nhl/standings',
      '/api/games',
      '/api/news',
      '/api/players',
      '/api/fantasy/teams',
      '/api/fantasyhub/players',
      '/api/picks/daily',
      '/api/parlay/suggestions',
      '/api/kalshi/predictions',
      '/api/prizepicks/selections',
      '/api/prizepicks/analytics',
      '/api/match/analytics',
      '/api/advanced/analytics',
      '/api/player/stats/trends',
      '/api/secret/phrases',
      '/api/subscription/plans',
      '/api/sportsbooks',
      '/api/auth/health',
      '/api/admin/health',
      '/api/cors-test',
      '/api/frontend-test'
    ]
  });
});

// ====================
// 404 HANDLER
// ====================
app.use('*', (req, res) => {
  const path = req.originalUrl;
  
  console.log(`❓ 404 Not Found: ${req.method} ${path}`);
  
  if (path.startsWith('/api/')) {
    res.status(404).json({
      success: false,
      error: 'API endpoint not found',
      message: 'API endpoint not found',
      path: path,
      timestamp: new Date().toISOString(),
      available: [
        '/api/nba',
        '/api/nba/games',
        '/api/nfl/games',
        '/api/nfl/stats',
        '/api/nfl/standings',
        '/api/nhl/games',
        '/api/nhl/players',
        '/api/nhl/standings',
        '/api/games',
        '/api/news',
        '/api/players',
        '/api/fantasy/teams',
        '/api/fantasyhub/players',
        '/api/picks/daily',
        '/api/parlay/suggestions',
        '/api/kalshi/predictions',
        '/api/prizepicks/selections',
        '/api/prizepicks/analytics',
        '/api/match/analytics',
        '/api/advanced/analytics',
        '/api/player/stats/trends',
        '/api/secret/phrases',
        '/api/subscription/plans',
        '/api/sportsbooks',
        '/api/auth/health',
        '/api/admin/health',
        '/api/cors-test',
        '/api/frontend-test'
      ],
      documentation: '/api-docs'
    });
  } else {
    res.status(404).json({
      success: false,
      error: 'Not found',
      message: 'Not found',
      path: path,
      timestamp: new Date().toISOString(),
      available: ['/', '/health', '/api', '/api-docs'],
      note: 'Visit /api for API endpoints or /api-docs for documentation'
    });
  }
});

// ====================
// ERROR HANDLER MIDDLEWARE
// ====================
const errorHandler = (err, req, res, next) => {
  console.error('🔥 ERROR:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });

  // Different error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors: err.errors
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized'
    });
  }

  // CORS errors
  if (err.message.includes('CORS')) {
    return res.status(403).json({
      success: false,
      error: 'CORS Error',
      message: err.message,
      allowedOrigins: allowedOrigins.map(o => typeof o === 'string' ? o : o.source)
    });
  }

  // Default error
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
};

// ====================
// ADD ERROR HANDLER AFTER ALL ROUTES
// ====================
app.use(errorHandler);

// ====================
// START SERVER
// ====================
async function startServer() {
  try {
    // Connect to MongoDB
    if (process.env.MONGODB_URI) {
      console.log('🔄 Connecting to MongoDB...');
      try {
        await mongoose.connect(process.env.MONGODB_URI, {
          serverSelectionTimeoutMS: 10000,
          socketTimeoutMS: 45000,
          maxPoolSize: 10
        });
        console.log('✅ MongoDB connected');
      } catch (error) {
        console.log('⚠️  MongoDB connection failed:', error.message);
        console.log('   Continuing without database connection');
      }
    }

    // Start server immediately
    const server = app.listen(PORT, HOST, () => {
      console.log(`\n🎉 Server running on ${HOST}:${PORT}`);
      console.log(`🌐 CORS Enabled for: ${allowedOrigins.length} origins`);
      console.log(`🔧 Trust proxy: ${app.get('trust proxy')}`);
      console.log(`🏥 Health: https://pleasing-determination-production.up.railway.app/health`);
      console.log(`📚 Docs: https://pleasing-determination-production.up.railway.app/api-docs`);
      console.log(`🔧 API: https://pleasing-determination-production.up.railway.app/api`);
      console.log(`🧪 Test: https://pleasing-determination-production.up.railway.app/api/test`);
      
      console.log(`\n🔧 RAILWAY FIXES APPLIED:`);
      console.log(`   1. Trust proxy enabled: ${app.get('trust proxy')}`);
      console.log(`   2. Enhanced PrizePicks fetcher with better headers`);
      console.log(`   3. Alternative state code fallback (NY, IL, NJ, PA, CA)`);
      console.log(`   4. Improved rate limiter configuration`);
      
      console.log(`\n🎯 KEY ENDPOINTS:`);
      console.log(`   GET /api/prizepicks/selections - Enhanced with Railway fixes`);
      console.log(`   GET /api/fantasyhub/players   - Resilient to API failures`);
      console.log(`   Rate Limiting: 15 requests/15 minutes (cached responses don't count)`);
      
      console.log(`\n✨ Server ready with Railway fixes!`);
      console.log(`⚡ PrizePicks will try multiple approaches if blocked`);
    });

    // Graceful shutdown
    const shutdown = () => {
      console.log('\n🛑 Shutting down gracefully...');
      
      // Close Redis connection
      if (redisClient) {
        redisClient.quit();
        console.log('✅ Redis connection closed');
      }
      
      // Close MongoDB connection
      if (mongoose.connection.readyState === 1) {
        mongoose.connection.close(false);
        console.log('✅ MongoDB connection closed');
      }
      
      server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
      });
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

// Start server
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}

export { app };

