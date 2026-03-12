// server.mjs - FINAL PRODUCTION v3.9 (with team name mapping, static opponent fallback, NHL per‑game stats)
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
import { createClient } from 'redis';

// Import services
import nbaApiService from './services/nbaApiService.js';
import DraftRecommendation from './models/DraftRecommendation.js';
import * as tank01Service from './services/tank01Service.js';
import * as sleeperService from './services/sleeperService.js';

const app = express();
const PORT = process.env.PORT || 3002;
const HOST = process.env.HOST || '0.0.0.0';

console.log('🚀 NBA Fantasy AI Backend - FINAL PRODUCTION v3.9 (with team name mapping & static opponent fallback)');
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);

// ====================
// REDIS CLIENTS
// ====================
let redisClient = null;
let redisCacheClient = null;

if (process.env.REDIS_URL) {
  try {
    redisClient = new Redis(process.env.REDIS_URL);
    redisClient.on('connect', () => console.log('✅ Redis connected (main)'));
    redisClient.on('error', (err) => console.log('Redis error:', err.message));

    const REDIS_CACHE_URL = process.env.REDIS_CACHE_URL || 'redis://default:INSrZrFpEBiQydygTJdrFrXgmbdCEBBz@metro.proxy.rlwy.net:48972';
    redisCacheClient = createClient({ url: REDIS_CACHE_URL });
    
    redisCacheClient.on('error', (err) => console.error('Redis Cache Error:', err));
    await redisCacheClient.connect();
    console.log('✅ Connected to Redis Cache');
  } catch (error) {
    console.log('⚠️  Redis connection failed:', error.message);
  }
}

// ====================
// CACHE CONFIGURATION (NodeCache as fallback)
// ====================
const cache = new NodeCache({ stdTTL: 300 }); // 5 minutes default

// ====================
// GLOBAL STATIC PLAYERS CACHE (from Python API)
// ====================
let staticNBAPlayers = [];
let staticNHLPlayers = [];
let staticMLBPlayers = [];
let staticNFLPlayers = [];

// ====================
// HELPER: CACHE UTILITY (with fixed Redis setEx)
// ====================
// Add this helper function near your other fetch functions
async function fetchTank01Roster(teamAbv, sport) {
  const cacheKey = `tank01:roster:${sport}:${teamAbv}`;
  return await getCachedOrFetch(cacheKey, async () => {
    const rosterData = await getCachedTank01Data('getTeamRoster', { 
      team: teamAbv, 
      sport,
      getStats: 'true',
      fantasyPoints: 'true' 
    }, 3600); // 1 hour cache
    
    return rosterData;
  }, 3600);
}

async function getCachedOrFetch(key, fetchFn, ttl = 300) {
  if (redisCacheClient) {
    try {
      const cached = await redisCacheClient.get(key);
      if (cached) {
        console.log(`✅ Serving ${key} from Redis cache`);
        return JSON.parse(cached);
      }
    } catch (error) {
      console.warn(`⚠️ Redis cache read failed for ${key}:`, error.message);
    }
  }
  
  const nodeCached = cache.get(key);
  if (nodeCached) {
    console.log(`✅ Serving ${key} from NodeCache`);
    return nodeCached;
  }
  
  console.log(`🔄 Fetching fresh data for ${key}`);
  const data = await fetchFn();
  
  if (redisCacheClient) {
    try {
      await redisCacheClient.set(key, JSON.stringify(data), { EX: ttl });
      console.log(`✅ Stored ${key} in Redis cache with TTL ${ttl}s`);
    } catch (error) {
      console.warn(`⚠️ Redis cache write failed for ${key}:`, error.message);
      cache.set(key, data, ttl);
    }
  } else {
    cache.set(key, data, ttl);
  }
  
  return data;
}

async function fetchNodeMasterWithRetry(sport = 'nba', maxRetries = 3) {
  const url = `https://prizepicks-production.up.railway.app/api/players/master?sport=${sport}`;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        if (response.status === 429 && attempt < maxRetries) {
          const delay = Math.pow(2, attempt) * 1000;
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        throw new Error(`HTTP ${response.status}`);
      }
      const result = await response.json();
      if (!result.success || !Array.isArray(result.data)) {
        throw new Error('Invalid data format from Node Master');
      }
      // Transform to a consistent format (mirrors fantasyhub transformation)
      return result.data.map(p => ({
        player_id: p.id,
        name: p.name,
        team: p.team,
        position: p.position,
        injury_status: p.injury_status || 'Healthy',
        points: p.points || 0,
        rebounds: p.rebounds || 0,
        assists: p.assists || 0,
        steals: p.steals || 0,
        blocks: p.blocks || 0,
        turnovers: p.turnovers || 0,
        fantasy_points: p.projection || p.fantasy_points || 0,
        salary: p.salary || 5000,
        games_played: p.games_played || 0,
        adp: p.adp,
        is_rookie: p.is_rookie || false,
        value: p.salary ? ((p.projection || 0) / p.salary) * 1000 : 0,
        source: 'node_master'
      }));
    } catch (err) {
      if (attempt === maxRetries) throw err;
      const delay = Math.pow(2, attempt) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('Max retries exceeded');
}

// ====================
// TEAM NAME TO ABBREVIATION MAPPING (NBA + NHL)
// ====================
const TEAM_NAME_TO_ABBR = {
  // NBA teams
  'Atlanta Hawks': 'ATL',
  'Boston Celtics': 'BOS',
  'Brooklyn Nets': 'BKN',
  'Charlotte Hornets': 'CHA',
  'Chicago Bulls': 'CHI',
  'Cleveland Cavaliers': 'CLE',
  'Dallas Mavericks': 'DAL',
  'Denver Nuggets': 'DEN',
  'Detroit Pistons': 'DET',
  'Golden State Warriors': 'GSW',
  'Houston Rockets': 'HOU',
  'Indiana Pacers': 'IND',
  'Los Angeles Clippers': 'LAC',
  'Los Angeles Lakers': 'LAL',
  'Memphis Grizzlies': 'MEM',
  'Miami Heat': 'MIA',
  'Milwaukee Bucks': 'MIL',
  'Minnesota Timberwolves': 'MIN',
  'New Orleans Pelicans': 'NOP',
  'New York Knicks': 'NYK',
  'Oklahoma City Thunder': 'OKC',
  'Orlando Magic': 'ORL',
  'Philadelphia 76ers': 'PHI',
  'Phoenix Suns': 'PHX',
  'Portland Trail Blazers': 'POR',
  'Sacramento Kings': 'SAC',
  'San Antonio Spurs': 'SAS',
  'Toronto Raptors': 'TOR',
  'Utah Jazz': 'UTA',
  'Washington Wizards': 'WAS',

  // NHL teams
  'Anaheim Ducks': 'ANA',
  'Arizona Coyotes': 'ARI',
  'Boston Bruins': 'BOS',
  'Buffalo Sabres': 'BUF',
  'Calgary Flames': 'CGY',
  'Carolina Hurricanes': 'CAR',
  'Chicago Blackhawks': 'CHI',
  'Colorado Avalanche': 'COL',
  'Columbus Blue Jackets': 'CBJ',
  'Dallas Stars': 'DAL',
  'Detroit Red Wings': 'DET',
  'Edmonton Oilers': 'EDM',
  'Florida Panthers': 'FLA',
  'Los Angeles Kings': 'LAK',
  'Minnesota Wild': 'MIN',
  'Montréal Canadiens': 'MTL',
  'Nashville Predators': 'NSH',
  'New Jersey Devils': 'NJD',
  'New York Islanders': 'NYI',
  'New York Rangers': 'NYR',
  'Ottawa Senators': 'OTT',
  'Philadelphia Flyers': 'PHI',
  'Pittsburgh Penguins': 'PIT',
  'San Jose Sharks': 'SJS',
  'Seattle Kraken': 'SEA',
  'St. Louis Blues': 'STL',
  'Tampa Bay Lightning': 'TBL',
  'Toronto Maple Leafs': 'TOR',
  'Vancouver Canucks': 'VAN',
  'Vegas Golden Knights': 'VGK',
  'Washington Capitals': 'WSH',
  'Winnipeg Jets': 'WPG'
};

function getTeamAbbreviation(fullName) {
  return TEAM_NAME_TO_ABBR[fullName] || fullName; // fallback to original if not found
}

// ====================
// TANK01 CACHED DATA FETCHER (with fixed Redis setEx)
// ====================
async function fetchTeamDefensiveStats(sport = 'nba') {
  const cacheKey = `tank01:defensive:${sport}`;
  return await getCachedOrFetch(cacheKey, async () => {
    const currentInfo = await getCachedTank01Data('getCurrentInfo', { sport }, 86400); // 24h cache
    const teams = currentInfo?.teamStats || currentInfo?.teams || [];
    const defensiveMap = new Map();
    teams.forEach(team => {
      defensiveMap.set(team.teamAbbrev, {
        pointsAllowed: parseFloat(team.oppg) || 0,
        reboundsAllowed: parseFloat(team.opprpg) || 0,
        assistsAllowed: parseFloat(team.oppapg) || 0,
      });
    });
    return defensiveMap;
  }, 3600); // 1 hour TTL
}

function computeLeagueAverages(defensiveMap) {
  let totalPoints = 0, totalRebs = 0, totalAsts = 0, count = 0;
  for (const stats of defensiveMap.values()) {
    totalPoints += stats.pointsAllowed;
    totalRebs += stats.reboundsAllowed;
    totalAsts += stats.assistsAllowed;
    count++;
  }
  return {
    points: count > 0 ? totalPoints / count : 110,
    rebounds: count > 0 ? totalRebs / count : 42,
    assists: count > 0 ? totalAsts / count : 24,
  };
}

async function getCachedTank01Data(endpoint, params = {}, ttl = 600) {
  const paramString = Object.keys(params).sort().map(key => `${key}:${params[key]}`).join(':');
  const cacheKey = `tank01:${endpoint}:${paramString}`;
  
  try {
    if (redisCacheClient) {
      const cached = await redisCacheClient.get(cacheKey);
      if (cached) {
        console.log(`✅ Tank01 Redis cache hit: ${endpoint}`);
        return JSON.parse(cached);
      }
    }
    
    console.log(`🔄 Fetching fresh Tank01 data: ${endpoint}`);
    let data;
    
    switch(endpoint) {
      case 'getNBAGamesForDate':
      case 'getGamesForDate':
        data = await tank01Service.getGamesForDate(params.gameDate, params.sport || 'nba');
        break;
      case 'getPlayerList':
        data = await tank01Service.getPlayerList(params.sport || 'nba');
        break;
      case 'getADP':
        data = await tank01Service.getADP(params.sport || 'nba');
        break;
      case 'getProjections':
        data = await tank01Service.getProjections(params.days || 7, params.sport || 'nba');
        break;
      case 'getInjuries':
        data = await tank01Service.getInjuries(params.sport || 'nba');
        break;
      case 'getNews':
        data = await tank01Service.getNews(params.max || 10, params.sport || 'nba');
        break;
      case 'getDepthCharts':
        data = await tank01Service.getDepthCharts(params.sport || 'nba');
        break;
      case 'getPlayerInfo':
        data = await tank01Service.getPlayerInfo(params.name, params.sport || 'nba');
        break;
      case 'getTeamRoster':
        data = await tank01Service.getTeamRoster(params.team, params.sport || 'nba');
        break;
      case 'getCurrentInfo':
        data = await tank01Service.getCurrentInfo(params.sport || 'nba');
        break;
      case 'getBoxScore':
        data = await tank01Service.getBoxScore(params.gameID, params.fantasyPoints === 'true', params.sport || 'nba');
        break;
      // NEW CASES FOR MLB & NHL TEAMS
      case 'getMLBTeams':
        data = await tank01Service.getMLBTeams();
        break;
      case 'getNHLTeams':
        data = await tank01Service.getNHLTeams();
        break;
      default:
        throw new Error(`Unknown endpoint: ${endpoint}`);
    }
    
    if (redisCacheClient) {
      await redisCacheClient.set(cacheKey, JSON.stringify(data), { EX: ttl });
      console.log(`✅ Stored Tank01 data in Redis: ${endpoint}`);
    }
    
    return data;
  } catch (error) {
    console.error(`Error in getCachedTank01Data for ${endpoint}:`, error);
    throw error;
  }
}

const DEFENSIVE_FACTORS = {
  'BOS': { points: 0.95, rebounds: 1.02, assists: 0.98, fantasy: 0.97 },
  'BKN': { points: 1.02, rebounds: 0.99, assists: 1.01, fantasy: 1.01 },
  'NYK': { points: 0.97, rebounds: 1.00, assists: 0.96, fantasy: 0.96 },
  'PHI': { points: 0.98, rebounds: 1.01, assists: 0.97, fantasy: 0.97 },
  'TOR': { points: 1.01, rebounds: 0.98, assists: 1.02, fantasy: 1.00 },
  'CHI': { points: 1.03, rebounds: 1.02, assists: 1.01, fantasy: 1.02 },
  'CLE': { points: 0.96, rebounds: 0.99, assists: 0.95, fantasy: 0.95 },
  'DET': { points: 1.05, rebounds: 1.04, assists: 1.03, fantasy: 1.04 },
  'IND': { points: 1.02, rebounds: 1.00, assists: 1.02, fantasy: 1.01 },
  'MIL': { points: 0.92, rebounds: 1.01, assists: 0.94, fantasy: 0.94 },
  'ATL': { points: 1.04, rebounds: 1.03, assists: 1.04, fantasy: 1.03 },
  'CHA': { points: 1.03, rebounds: 1.02, assists: 1.02, fantasy: 1.02 },
  'MIA': { points: 0.96, rebounds: 0.98, assists: 0.97, fantasy: 0.96 },
  'ORL': { points: 0.97, rebounds: 1.00, assists: 0.98, fantasy: 0.97 },
  'WAS': { points: 1.06, rebounds: 1.03, assists: 1.05, fantasy: 1.05 },
  'DEN': { points: 1.02, rebounds: 0.95, assists: 1.03, fantasy: 1.00 },
  'MIN': { points: 0.94, rebounds: 0.96, assists: 0.95, fantasy: 0.94 },
  'OKC': { points: 0.93, rebounds: 0.97, assists: 0.94, fantasy: 0.93 },
  'POR': { points: 1.04, rebounds: 1.02, assists: 1.03, fantasy: 1.03 },
  'UTA': { points: 1.01, rebounds: 0.99, assists: 1.02, fantasy: 1.00 },
  'GSW': { points: 0.98, rebounds: 1.01, assists: 0.97, fantasy: 0.97 },
  'LAC': { points: 0.97, rebounds: 0.98, assists: 0.98, fantasy: 0.96 },
  'LAL': { points: 1.08, rebounds: 0.97, assists: 1.05, fantasy: 1.04 },
  'PHX': { points: 1.05, rebounds: 0.99, assists: 1.03, fantasy: 1.02 },
  'SAC': { points: 1.03, rebounds: 1.02, assists: 1.02, fantasy: 1.02 },
  'DAL': { points: 1.02, rebounds: 1.01, assists: 1.02, fantasy: 1.01 },
  'HOU': { points: 1.04, rebounds: 1.03, assists: 1.03, fantasy: 1.03 },
  'MEM': { points: 0.95, rebounds: 0.96, assists: 0.96, fantasy: 0.95 },
  'NOP': { points: 1.01, rebounds: 1.02, assists: 1.00, fantasy: 1.01 },
  'SAS': { points: 0.99, rebounds: 1.00, assists: 0.99, fantasy: 0.99 }
};

// ====================
// FETCH STATIC NBA PLAYERS (from Python API)
// ====================

async function fetchStaticNBAPlayers() {
  const pythonApiUrl = process.env.PYTHON_API_URL || 'https://python-api-fresh-production.up.railway.app';
  try {
    console.log('📡 Fetching static NBA players from Python API...');
    const response = await axios.get(`${pythonApiUrl}/api/fantasy/players`, {
      params: { sport: 'nba', realtime: 'false', limit: 500 },
      timeout: 10000
    });
    if (response.data.success && Array.isArray(response.data.players)) {
      console.log(`✅ Loaded ${response.data.players.length} static NBA players`);
      if (response.data.players.length > 0) {
        console.log('🔍 First player from Python:', {
          name: response.data.players[0].name,
          points: response.data.players[0].points,
          rebounds: response.data.players[0].rebounds,
          assists: response.data.players[0].assists,
          fantasy_points: response.data.players[0].fantasy_points
        });
      }
      return response.data.players;
    }
    console.warn('⚠️ Python API returned no players, using empty array');
    return [];
  } catch (error) {
    console.error('❌ Failed to fetch static NBA players from Python API:', error.message);
    return [];
  }
}

// ====================
// FETCH STATIC NHL PLAYERS (from Python API) – CORRECTED VERSION
// ====================
async function fetchStaticMLBPlayers() {
  const pythonApiUrl = process.env.PYTHON_API_URL || 'https://python-api-fresh-production.up.railway.app';
  try {
    console.log('📡 Fetching static MLB players from Python API...');
    const response = await axios.get(`${pythonApiUrl}/api/players`, {
      params: { sport: 'mlb', realtime: 'false', limit: 500 },
      timeout: 10000
    });
    if (response.data?.data?.players) {
      const players = response.data.data.players;
      console.log(`✅ Raw MLB players count: ${players.length}`);
      // Map to consistent format (similar to NHL mapping)
      const mapped = players.map(p => ({
        id: p.id || `mlb-${p.name.replace(/\s+/g, '-')}`,
        name: p.name,
        team: p.team,
        position: p.position,
        points: p.points || 0,
        fantasy_points: p.fantasy_points || 0,
        injury_status: p.injury_status || 'Healthy',
        salary: p.salary || 5000,
        games_played: p.games_played || 1,
        adp: p.adp
      }));
      console.log(`✅ Mapped ${mapped.length} static MLB players`);
      return mapped;
    }
    return [];
  } catch (error) {
    console.error('❌ Failed to fetch static MLB players:', error.message);
    return [];
  }
}

async function fetchStaticNHLPlayers() {
  const pythonApiUrl = process.env.PYTHON_API_URL || 'https://python-api-fresh-production.up.railway.app';
  try {
    console.log('📡 Fetching static NHL players from Python API...');
    const response = await axios.get(`${pythonApiUrl}/api/players`, {
      params: { sport: 'nhl', realtime: 'false', limit: 500 },
      timeout: 10000
    });

    if (response.data?.data?.players) {
      const players = response.data.data.players;
      console.log(`✅ Raw NHL players count: ${players.length}`);

      const mappedPlayers = players.map(p => {
        const games = p.games_played || 1;
        
        return {
          id: p.id || `nhl-${p.name.replace(/\s+/g, '-')}`,
          name: p.name,
          team: p.team,
          position: p.position,
          
          // Per-game stats (already have these)
          points: (p.points || 0) / games,
          assists: (p.assists || 0) / games,
          fantasy_points: p.fantasy_points || 0,
          
          // NHL-specific stats from your curl response
          goals: (p.goals || 0) / games,
          plusMinus: p.plusMinus || 0,
          shots: (p.shots || 0) / games,
          hits: (p.hits || 0) / games,
          blockedShots: (p.blockedShots || 0) / games,
          timeOnIce: p.timeOnIce || '0:00',
          powerPlayGoals: (p.powerPlayGoals || 0) / games,
          powerPlayAssists: (p.powerPlayAssists || 0) / games,
          powerPlayPoints: (p.powerPlayPoints || 0) / games,
          faceoffsWon: (p.faceoffsWon || 0) / games,
          faceoffsLost: (p.faceoffsLost || 0) / games,
          faceoffs: (p.faceoffs || 0) / games,
          penalties: (p.penalties || 0) / games,
          penaltiesInMinutes: (p.penaltiesInMinutes || 0) / games,
          shifts: p.shifts || 0,
          takeaways: (p.takeaways || 0) / games,
          giveaways: (p.giveaways || 0) / games,
          shotsMissedNet: (p.shotsMissedNet || 0) / games,
          
          // Original fields
          injury_status: p.injury_status || 'Healthy',
          salary: 5000,
          games_played: games
        };
      });

      console.log(`✅ Mapped ${mappedPlayers.length} static NHL players with enhanced stats`);
      return mappedPlayers;
    }
    return [];
  } catch (error) {
    console.error('❌ Failed to fetch static NHL players:', error.message);
    return [];
  }
}

// Tank01 master data cache (refreshed every hour)
let tank01MasterCache = null;
let tank01CacheTime = 0;
const TANK01_CACHE_TTL = 60 * 60 * 1000; // 1 hour

async function getTank01MasterData(sport = 'nba') {
  const cacheKey = `tank01:master:${sport}`;
  if (redisCacheClient) {
    try {
      const cached = await redisCacheClient.get(cacheKey);
      if (cached) {
        console.log(`✅ Serving Tank01 master data from Redis cache`);
        const parsed = JSON.parse(cached);
        return new Map(parsed);
      }
    } catch (error) {
      console.warn('⚠️ Redis cache read failed for Tank01 master:', error.message);
    }
  }

  if (tank01MasterCache && (Date.now() - tank01CacheTime) < TANK01_CACHE_TTL) {
    return tank01MasterCache;
  }

  try {
    const [playerList, projections, adpList, injuries] = await Promise.all([
      getCachedTank01Data('getPlayerList', { sport }, 3600),
      getCachedTank01Data('getProjections', { days: 7, sport }, 1800),
      getCachedTank01Data('getADP', { sport }, 3600),
      getCachedTank01Data('getInjuries', { sport }, 600)
    ]);

    const playerMap = new Map();
    if (Array.isArray(playerList)) {
      playerList.forEach(p => {
        playerMap.set(p.playerID, {
          name: p.longName,
          team: p.team,
          position: p.pos,
          playerID: p.playerID
        });
      });
    }

    const projectionMap = new Map();
    if (projections) {
      Object.entries(projections).forEach(([id, proj]) => {
        projectionMap.set(id, proj);
      });
    }

    const adpMap = new Map();
    if (Array.isArray(adpList)) {
      adpList.forEach(item => {
        adpMap.set(item.playerID, parseFloat(item.overallADP) || 999);
      });
    }

    const injurySet = new Set();
    if (Array.isArray(injuries)) {
      injuries.forEach(inj => {
        if (inj.playerID) injurySet.add(inj.playerID);
      });
    }

    const masterMap = new Map();
    const gamesInPeriod = 7;

    for (const [id, basic] of playerMap.entries()) {
      const proj = projectionMap.get(id);
      const pointsPerGame = proj?.pts ? parseFloat(proj.pts) / gamesInPeriod : undefined;
      const reboundsPerGame = proj?.reb ? parseFloat(proj.reb) / gamesInPeriod : undefined;
      const assistsPerGame = proj?.ast ? parseFloat(proj.ast) / gamesInPeriod : undefined;
      const fantasyPerGame = proj?.fantasyPoints ? parseFloat(proj.fantasyPoints) / gamesInPeriod : undefined;

      masterMap.set(id, {
        ...basic,
        adp: adpMap.get(id),
        injury_status: injurySet.has(id) ? 'Injured' : 'Healthy',
        points: pointsPerGame,
        rebounds: reboundsPerGame,
        assists: assistsPerGame,
        projection: fantasyPerGame,
      });
    }

    tank01MasterCache = masterMap;
    tank01CacheTime = Date.now();

    if (redisCacheClient) {
      try {
        const serialized = JSON.stringify(Array.from(masterMap.entries()));
        await redisCacheClient.set(cacheKey, serialized, { EX: 3600 });
        console.log(`✅ Stored Tank01 master data in Redis cache`);
      } catch (error) {
        console.warn('⚠️ Redis cache write failed:', error.message);
      }
    }

    return masterMap;
  } catch (error) {
    console.error('Error fetching Tank01 master data:', error);
    return new Map();
  }
}

// ====================
// CORS CONFIGURATION
// ====================
const allowedOrigins = [
  'https://sportsanalyticsgpt.com',
  'https://www.sportsanalyticsgpt.com',
  'https://nba-frontend-web.vercel.app',
  'https://nba-frontend-web-git-main-jarryexon-2517s-projects.vercel.app',
  'https://februaryfantasy-production.up.railway.app',
  'http://februaryfantasy-production.up.railway.app',
  'https://pleasing-determination-production.up.railway.app',
  'http://pleasing-determination-production.up.railway.app',
  'https://prizepicks-production.up.railway.app',
  'http://prizepicks-production.up.railway.app',
  'http://localhost:19006',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:3002',
  'http://localhost:8080',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:3001',
  'http://127.0.0.1:3002',
  'http://127.0.0.1:5173',
  /\.vercel\.app$/,
  /\.railway\.app$/,
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') return origin === allowedOrigin;
      if (allowedOrigin instanceof RegExp) return allowedOrigin.test(origin);
      return false;
    });
    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy: Origin ${origin} is not allowed`), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
  allowedHeaders: [
    'Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key',
    'Accept', 'Origin', 'X-CSRF-Token', 'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ],
  exposedHeaders: ['Content-Range', 'X-Content-Range', 'X-Request-ID'],
  maxAge: 86400,
  optionsSuccessStatus: 204,
  preflightContinue: false
};

app.use(cors(corsOptions));

// ====================
// PREFLIGHT HANDLER
// ====================
app.options('*', (req, res) => {
  const origin = req.headers.origin;
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
    res.status(403).json({ error: 'CORS preflight failed' });
  }
});

// ====================
// TRUST PROXY, SECURITY, PERFORMANCE
// ====================
app.set('trust proxy', 1);
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
// RATE LIMITERS
// ====================
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// ====================
// REQUEST LOGGING
// ====================
app.use((req, res, next) => {
  const start = Date.now();
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  console.log(`[${requestId}] ${req.method} ${req.originalUrl}`, {
    origin: req.headers.origin || 'no-origin',
    'user-agent': req.headers['user-agent']?.substring(0, 50)
  });
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
      version: '3.9.0',
      description: 'NBA Fantasy AI Backend API Documentation (with Tank01 Redis caching + Opponent Adjustments + Static Fallback)',
      license: { name: 'MIT', url: 'https://opensource.org/licenses/MIT' }
    },
    servers: [
      { url: 'https://prizepicks-production.up.railway.app', description: 'Production server' },
      { url: 'http://localhost:3002', description: 'Local development server' }
    ],
    components: {
      securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
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
// RESPONSE CONVERTER MIDDLEWARE
// ====================
app.use((req, res, next) => {
  console.log(`🛠️ Request to: ${req.path}`);
  const originalJson = res.json;
  res.json = function(data) {
    console.log(`🛠️ Response for ${req.path}:`, data?.success ? 'Success' : 'Failed');
    if (data && data.success === true) {
      if (req.path.includes('/nfl/standings') && data.standings && typeof data.standings === 'object' && !Array.isArray(data.standings)) {
        const allTeams = [];
        if (data.standings.afc) {
          data.standings.afc.forEach(division => {
            if (division.teams) allTeams.push(...division.teams.map(team => ({ ...team, conference: 'AFC', division: division.division })));
          });
        }
        if (data.standings.nfc) {
          data.standings.nfc.forEach(division => {
            if (division.teams) allTeams.push(...division.teams.map(team => ({ ...team, conference: 'NFC', division: division.division })));
          });
        }
        data.standings = allTeams;
      }
      if (req.path.includes('/nhl/standings') && data.standings && typeof data.standings === 'object' && !Array.isArray(data.standings)) {
        const allTeams = [];
        if (data.standings.eastern) {
          data.standings.eastern.forEach(division => {
            if (division.teams) allTeams.push(...division.teams.map(team => ({ ...team, conference: 'Eastern', division: division.division })));
          });
        }
        if (data.standings.western) {
          data.standings.western.forEach(division => {
            if (division.teams) allTeams.push(...division.teams.map(team => ({ ...team, conference: 'Western', division: division.division })));
          });
        }
        data.standings = allTeams;
      }
    }
    return originalJson.call(this, data);
  };
  next();
});
console.log('🔧 Response converter middleware loaded - BEFORE all routes');

// ====================
// CACHE HEALTH ENDPOINT
// ====================
app.get('/api/health/cache', async (req, res) => {
  try {
    let redisStatus = 'disabled';
    let redisTest = 'not tested';
    
    if (redisCacheClient) {
      try {
        await redisCacheClient.set('health:test', 'ok', { EX: 10 });
        const test = await redisCacheClient.get('health:test');
        redisTest = test === 'ok' ? 'passed' : 'failed';
        redisStatus = 'connected';
      } catch (error) {
        redisStatus = 'error';
        redisTest = error.message;
      }
    }
    
    const nodeCacheStats = cache.getStats();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      redis: {
        status: redisStatus,
        test: redisTest,
        client: redisCacheClient ? 'initialized' : 'not initialized'
      },
      nodeCache: {
        hits: nodeCacheStats.hits || 0,
        misses: nodeCacheStats.misses || 0,
        keys: cache.keys().length,
        size: JSON.stringify(cache.mget(cache.keys())).length
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      redis: 'error',
      error: error.message
    });
  }
});

app.get('/api/debug/draft-params', function(req, res) {
  console.log('🔍 Debug draft params:', req.query);
  res.json({
    received_params: req.query,
    pick_value: req.query.pick,
    pick_type: typeof req.query.pick,
    parsed_pick: parseInt(req.query.pick, 10)
  });
});

// ====================
// BASIC ENDPOINTS
// ====================
app.get('/', (req, res) => {
  res.json({
    service: 'NBA Fantasy AI Backend',
    version: '3.9.0',
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    documentation: '/api-docs',
    health: '/health',
    cacheHealth: '/api/health/cache',
    api: '/api',
    cors: { enabled: true, allowedOrigins: allowedOrigins.map(o => typeof o === 'string' ? o : o.source) },
    endpoints: {
      prizePicksData: '/api/prizepicks/selections',
      fantasyHubData: '/api/fantasyhub/players',
      oddsApiProps: '/api/theoddsapi/playerprops'
    },
    caching: {
      redis: redisCacheClient ? 'connected' : 'disabled',
      nodeCache: 'active (fallback)',
      ttl: '300 seconds default'
    },
    data_sources: {
      nba_api_service: 'Active (NBA Data API)',
      the_odds_api: process.env.ODDS_API_KEY ? 'Key present' : 'Key missing (using fallback)',
      static_2026_python: staticNBAPlayers.length > 0 ? `Loaded ${staticNBAPlayers.length} players` : 'Not loaded yet'
    }
  });
});

app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '3.9.0',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: redisCacheClient ? 'connected' : 'disabled',
    mongodb: 'disconnected',
    cors: { origin: req.headers.origin || 'none', allowed: true },
    api_sources: {
      nba_api_service: 'active',
      the_odds_api: process.env.ODDS_API_KEY ? 'key found' : 'key missing',
      rapidapi_key: process.env.RAPIDAPI_KEY ? 'present' : 'missing',
      static_2026_python: staticNBAPlayers.length
    }
  };
  if (mongoose.connection.readyState === 1) health.mongodb = 'connected';
  res.json(health);
});

app.get('/railway-health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    service: 'NBA Fantasy API',
    version: '3.9.0',
    cors: { clientOrigin: req.headers.origin || 'unknown', allowed: true },
    api_integrations: { nba_api_service: 'active', the_odds_api: process.env.ODDS_API_KEY ? 'key found' : 'key missing', static_2026_python: staticNBAPlayers.length }
  });
});

app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'NBA Fantasy AI API Gateway',
    version: '3.9.0',
    timestamp: new Date().toISOString(),
    client: { origin: req.headers.origin || 'unknown', ip: req.ip, userAgent: req.headers['user-agent'] },
    documentation: { swaggerUI: '/api-docs', swaggerJSON: '/api-docs.json' },
    coreEndpoints: [
      { path: '/api/nba', description: 'NBA data and statistics' },
      { path: '/api/auth/health', description: 'Authentication service health' },
      { path: '/api/admin/health', description: 'Administration service health' },
      { path: '/api/user', description: 'User management' },
      { path: '/api/games', description: 'Game schedules and results' },
      { path: '/api/news', description: 'Sports news and updates' },
      { path: '/api/sportsbooks', description: 'Sports betting data' },
      { path: '/api/prizepicks/selections', description: 'PrizePicks selections (The Odds API + 2026 static data + opponent adjustments)' },
      { path: '/api/fantasyhub/players', description: 'Fantasy Hub with NBA API stats + 2026 static base + opponent adjustments' },
      { path: '/api/theoddsapi/playerprops', description: 'Direct The Odds API player props (enriched with static data)' },
      { path: '/api/system/status', description: 'System status and API health' },
      { path: '/api/health/cache', description: 'Cache health and statistics' }
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
      redis: redisCacheClient ? 'connected' : 'disabled',
      nodeCache: 'active',
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    },
    api_integrations: {
      nba_api_service: 'active',
      the_odds_api: process.env.ODDS_API_KEY ? 'key found' : 'key missing',
      rapidapi_key: process.env.RAPIDAPI_KEY ? 'present' : 'missing',
      static_2026_python: staticNBAPlayers.length
    }
  });
});

// ====================
// SLEEPER API ENDPOINTS
// ====================
function getCurrentWeek() {
  const now = new Date();
  const start = new Date(now.getFullYear(), 0, 1);
  const days = Math.floor((now.getTime() - start.getTime()) / (24 * 60 * 60 * 1000));
  return Math.ceil(days / 7);
}

app.get('/api/sleeper/leagues', async (req, res) => {
  const cacheKey = `sleeper:leagues:${req.query.username || 'jerryjiya'}:${req.query.sport || 'nba'}:${req.query.season || '2025'}`;
  
  try {
    const data = await getCachedOrFetch(
      cacheKey,
      async () => {
        const { username = 'jerryjiya', sport = 'nba', season = '2025' } = req.query;
        return await sleeperService.getUserLeagues(username, sport, season);
      },
      600
    );
    
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/sleeper/rosters', async (req, res) => {
  const { leagueId } = req.query;
  if (!leagueId) return res.status(400).json({ success: false, error: 'leagueId required' });
  
  const cacheKey = `sleeper:rosters:${leagueId}`;
  
  try {
    const data = await getCachedOrFetch(
      cacheKey,
      async () => await sleeperService.getLeagueRosters(leagueId),
      300
    );
    
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/sleeper/players', async (req, res) => {
  const { sport = 'nba' } = req.query;
  const cacheKey = `sleeper:players:${sport}`;
  
  try {
    const data = await getCachedOrFetch(
      cacheKey,
      async () => await sleeperService.getAllPlayers(sport),
      3600
    );
    
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ====================
// TANK01 ENDPOINTS
// ====================
app.get('/api/tank01/teams', async (req, res) => {
  const { league } = req.query; // 'mlb' or 'nhl'
  if (!league || (league !== 'mlb' && league !== 'nhl')) {
    return res.status(400).json({ success: false, error: 'Invalid league' });
  }
  try {
    const data = await getCachedTank01Data(
      league === 'mlb' ? 'getMLBTeams' : 'getNHLTeams',
      {},
      86400 // 24h cache
    );
    // Transform to { abbreviation, fullName, logo } format
    const teams = (Array.isArray(data) ? data : []).map(t => ({
      abbreviation: t.teamAbv || t.abbreviation,
      fullName: t.teamName || t.fullName,
      logo: t.logos?.[0] || null,
    }));
    res.json({ success: true, data: teams });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/players', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const data = await getCachedTank01Data('getPlayerList', { sport }, 3600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/adp', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const data = await getCachedTank01Data('getADP', { sport }, 3600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/projections', async (req, res) => {
  try {
    const { days = 7, sport = 'nba' } = req.query;
    const data = await getCachedTank01Data('getProjections', { days: parseInt(days), sport }, 1800);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/injuries', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const data = await getCachedTank01Data('getInjuries', { sport }, 600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/news', async (req, res) => {
  try {
    const { max = 10, sport = 'nba' } = req.query;
    const data = await getCachedTank01Data('getNews', { max: parseInt(max), sport }, 600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/depthcharts', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const data = await getCachedTank01Data('getDepthCharts', { sport }, 3600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/games', async (req, res) => {
  try {
    const { date, sport = 'nba' } = req.query;
    if (!date) return res.status(400).json({ success: false, error: 'date required (YYYYMMDD)' });
    
    const data = await getCachedTank01Data('getGamesForDate', { gameDate: date, sport }, 300);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/player', async (req, res) => {
  try {
    const { name, sport = 'nba' } = req.query;
    if (!name) return res.status(400).json({ success: false, error: 'name required' });
    
    const data = await getCachedTank01Data('getPlayerInfo', { name, sport }, 3600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/roster', async (req, res) => {
  try {
    const { team, sport = 'nba' } = req.query;
    if (!team) return res.status(400).json({ success: false, error: 'team abbreviation required' });
    
    const data = await getCachedTank01Data('getTeamRoster', { team, sport }, 3600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/currentinfo', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const data = await getCachedTank01Data('getCurrentInfo', { sport }, 600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tank01/boxscore', async (req, res) => {
  try {
    const { gameID, fantasyPoints = 'true', sport = 'nba' } = req.query;
    if (!gameID) return res.status(400).json({ success: false, error: 'gameID required' });
    
    const data = await getCachedTank01Data('getBoxScore', { gameID, fantasyPoints, sport }, 600);
    res.json({ success: true, data, source: 'redis-cache' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/players/master
app.get('/api/players/master', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    if (sport !== 'nba') {
      return res.json({ success: true, data: [], count: 0, message: 'Only NBA supported' });
    }

    const cacheKey = `players:master:api:${sport}`;
    
    const data = await getCachedOrFetch(
      cacheKey,
      async () => {
        if (process.env.RAPIDAPI_KEY) {
          try {
            console.log('📡 Fetching from API-BASKETBALL (RapidAPI)...');
            const apiPlayers = await fetchFromAPIBasketball();
            if (apiPlayers && apiPlayers.length > 0) {
              console.log(`✅ Loaded ${apiPlayers.length} players from API-BASKETBALL`);
              return apiPlayers;
            }
          } catch (apiError) {
            console.error('❌ API-BASKETBALL failed:', apiError.message);
          }
        } else {
          console.log('⚠️ RAPIDAPI_KEY not set – skipping API');
        }

        // ✅ Use the 2026 static players if available
        if (staticNBAPlayers && staticNBAPlayers.length > 0) {
          console.log(`🔄 Using static 2026 NBA players (${staticNBAPlayers.length})`);
          return staticNBAPlayers;
        }

        console.log('⚠️ No static players, using curated fallback');
        return generateIntelligentFantasyFallback();
      },
      1800
    );

    res.json({ success: true, data, count: data.length, source: data[0]?.source || 'curated' });

  } catch (error) {
    console.error('🔥 Fatal error in /api/players/master:', error);
    const emergency = generateIntelligentFantasyFallback().slice(0, 3);
    res.json({ success: true, data: emergency, count: emergency.length, source: 'emergency' });
  }
});

// ====================
// PRIZEPICKS ENDPOINT
// ====================
async function fetchPlayerPropsFromOddsAPI(sport = 'basketball_nba') {
  console.log(`🎯 [The Odds API] Fetching player props for ${sport}...`);

  const API_KEY = process.env.ODDS_API_KEY || process.env.THE_ODDS_API_KEY;
  if (!API_KEY) {
    console.log('   ⚠️ No Odds API key found, returning empty');
    return [];
  }

  const BASE_URL = 'https://api.the-odds-api.com/v4';
  try {
    const gamesResponse = await axios.get(`${BASE_URL}/sports/${sport}/odds`, {
      params: { apiKey: API_KEY, regions: 'us', markets: 'h2h', oddsFormat: 'decimal' },
      timeout: 10000
    });
    const games = gamesResponse.data;
    if (!games || games.length === 0) return [];

    // Log a sample game to see the exact field names (temporary)
    if (games.length > 0) {
      console.log('📦 Sample game data from Odds API:', JSON.stringify(games[0], null, 2));
    }

    const allPlayerProps = [];
    const markets = ['player_points', 'player_rebounds', 'player_assists'];
    for (const game of games.slice(0, 2)) {
      try {
        const eventData = (await axios.get(`${BASE_URL}/sports/${sport}/events/${game.id}/odds`, {
          params: { apiKey: API_KEY, regions: 'us', markets: markets.join(','), oddsFormat: 'decimal' },
          timeout: 15000
        })).data;

        // Extract team abbreviations – use the exact field names from the API
        const homeTeam = game.home_team;          // might be "Los Angeles Lakers"
        const awayTeam = game.away_team;
        // If the API provides abbreviations directly, use those (e.g. game.home_team_abbr)
        const homeAbbr = game.home_team_abbr || getTeamAbbreviation(homeTeam);
        const awayAbbr = game.away_team_abbr || getTeamAbbreviation(awayTeam);

        for (const bookmaker of eventData.bookmakers || []) {
          for (const market of bookmaker.markets || []) {
            if (!markets.includes(market.key)) continue;
            for (const outcome of market.outcomes || []) {
              allPlayerProps.push({
                game: `${game.away_team} @ ${game.home_team}`,
                away_team_full: game.away_team,
                home_team_full: game.home_team,
                away_team_abbr: awayAbbr,
                home_team_abbr: homeAbbr,
                player: outcome.description || outcome.name,
                prop_type: market.key.replace('player_', ''),
                line: outcome.point || 0,
                type: outcome.name,
                bookmaker: bookmaker.title,
                odds: outcome.price,
                commence_time: game.commence_time,
                source: 'the-odds-api'
              });
            }
          }
        }
      } catch (e) {
        console.log(`   ⚠️ Skipping game ${game.id}: ${e.message}`);
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    console.log(`   ✅ Total player props collected: ${allPlayerProps.length}`);
    return allPlayerProps;
  } catch (error) {
    console.error('Error in fetchPlayerPropsFromOddsAPI:', error);
    return [];
  }
}

async function fetchFromAPIBasketball() {
  const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY;
  if (!RAPIDAPI_KEY) return [];

  try {
    console.log('📡 Fetching from API-Basketball-NBA (RapidAPI)...');
    const playersRes = await axios.get('https://api-basketball-nba.p.rapidapi.com/players/id', {
      headers: {
        'X-RapidAPI-Key': RAPIDAPI_KEY,
        'X-RapidAPI-Host': 'api-basketball-nba.p.rapidapi.com'
      },
      timeout: 15000
    });

    const players = playersRes.data || [];
    if (!players.length) {
      console.log('⚠️ No players returned from /players/id');
      return [];
    }

    console.log(`✅ Found ${players.length} players. Fetching stats for first 30...`);
    const statsPromises = players.slice(0, 30).map(async (player) => {
      try {
        const statsRes = await axios.get('https://api-basketball-nba.p.rapidapi.com/player/splits', {
          params: {
            playerId: player.id,
            year: '2024',
            category: 'perGame'
          },
          headers: {
            'X-RapidAPI-Key': RAPIDAPI_KEY,
            'X-RapidAPI-Host': 'api-basketball-nba.p.rapidapi.com'
          },
          timeout: 10000
        });

        const stats = statsRes.data?.player_stats || statsRes.data || {};

        return {
          id: player.id,
          name: `${player.firstName} ${player.lastName}`,
          team: player.teamAbbreviation || player.team || 'FA',
          position: player.position || 'N/A',
          points: stats.ppg || 0,
          rebounds: stats.rpg || 0,
          assists: stats.apg || 0,
          fantasy_points: (stats.ppg || 0) + 1.2*(stats.rpg || 0) + 1.5*(stats.apg || 0),
          salary: 5000,
          injury_status: 'Healthy',
          source: 'api-basketball'
        };
      } catch (err) {
        console.warn(`   ⚠️ Failed for player ${player.id} (${player.firstName} ${player.lastName}): ${err.message}`);
        return null;
      }
    });

    const results = (await Promise.all(statsPromises)).filter(p => p !== null);
    console.log(`✅ Fetched ${results.length} players from API-Basketball`);
    return results;
  } catch (error) {
    console.error('❌ API-Basketball fetch failed:', error.message);
    return [];
  }
}

function findStaticPlayer(playerName) {
  if (!staticNBAPlayers.length) return null;
  return staticNBAPlayers.find(p =>
    playerName.toLowerCase().includes(p.name.toLowerCase()) ||
    p.name.toLowerCase().includes(playerName.toLowerCase())
  );
}

const capitalize = (str) => str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();

// PrizePicks Selections Endpoint with Full Opponent Adjustment Integration
// ============================================================================
app.get('/api/prizepicks/selections', async (req, res) => {
  try {
    const sport = req.query.sport || 'nba';
    const sportKey = {
      nba: 'basketball_nba',
      nfl: 'americanfootball_nfl',
      nhl: 'icehockey_nhl',
      mlb: 'baseball_mlb'
    }[sport] || 'basketball_nba';

    const cacheKey = `prizepicks:selections:python:${sport}`;

    console.log(`🎰 [PrizePicks] Request for ${sport.toUpperCase()}`);

    // ========== Load sport‑specific static player data ==========
    const pythonPlayerMap = new Map();
    let staticPlayers = [];
    if (sport === 'nba') staticPlayers = staticNBAPlayers;
    else if (sport === 'nhl') staticPlayers = staticNHLPlayers;
    else if (sport === 'mlb') staticPlayers = staticMLBPlayers;
    else if (sport === 'nfl') staticPlayers = staticNFLPlayers;

    if (staticPlayers && staticPlayers.length > 0) {
      staticPlayers.forEach(p => {
        pythonPlayerMap.set(p.name.toLowerCase(), p);
        pythonPlayerMap.set(p.name.toLowerCase().replace(/\s+/g, ''), p);
      });
      console.log(`✅ Loaded ${staticPlayers.length} static ${sport.toUpperCase()} players into map`);
    } else {
      console.warn(`⚠️ static${sport.toUpperCase()}Players is empty – will fall back to generated fallback`);
    }

    const responsePayload = await getCachedOrFetch(
      cacheKey,
      async () => {
        let selections = [];
        let source = 'python-fallback';

        try {
          const playerProps = await fetchPlayerPropsFromOddsAPI(sportKey);
          if (!playerProps || playerProps.length === 0) {
            throw new Error('No props from The Odds API');
          }
          console.log(`   ✅ Fetched ${playerProps.length} props from The Odds API for ${sport}`);

          let tank01Master = new Map();
          try {
            tank01Master = await getTank01MasterData(sport);
            console.log(`   ✅ Fetched Tank01 master data with ${tank01Master.size} entries`);
          } catch (tankError) {
            console.warn(`   ⚠️ Tank01 fetch failed for ${sport}, using Python only:`, tankError.message);
          }

          // Fetch defensive stats (may be empty)
          let defensiveStatsMap = new Map();
          let leagueAverages = { points: 110, rebounds: 42, assists: 24 };
          try {
            defensiveStatsMap = await fetchTeamDefensiveStats(sport);
            if (defensiveStatsMap.size > 0) {
              leagueAverages = computeLeagueAverages(defensiveStatsMap);
            }
            console.log(`   ✅ Fetched defensive stats for ${defensiveStatsMap.size} teams`);
          } catch (defError) {
            console.warn('   ⚠️ Could not fetch defensive stats, opponent adjustment will be skipped:', defError.message);
          }

          const normalizeName = (name) => name.toLowerCase().replace(/[^a-z0-9]/g, '');

          selections = playerProps.map((prop, index) => {
            const playerKey = prop.player.toLowerCase().replace(/\s+/g, '');
            let pythonPlayer = pythonPlayerMap.get(playerKey) || pythonPlayerMap.get(prop.player.toLowerCase());

            // ----- LAST NAME FALLBACK -----
            if (!pythonPlayer) {
              const lastName = prop.player.split(' ').pop().toLowerCase();
              for (const [key, p] of pythonPlayerMap.entries()) {
                if (key.includes(lastName) || p.name.toLowerCase().includes(lastName)) {
                  pythonPlayer = p;
                  console.log(`   🔍 Matched by last name: ${prop.player} -> ${p.name}`);
                  break;
                }
              }
            }

            // ----- FIND TANK01 MATCH (for team and possibly projection) -----
            let matchedTank01 = null;
            if (tank01Master.size > 0) {
              const normalizedPropName = normalizeName(prop.player);
              for (const [id, data] of tank01Master.entries()) {
                if (!data.name) continue;
                const normalizedTankName = normalizeName(data.name);
                if (normalizedPropName.includes(normalizedTankName) || normalizedTankName.includes(normalizedPropName)) {
                  matchedTank01 = data;
                  break;
                }
              }
            }

            // Determine projection (prefer Python, then Tank01, then line)
            let projectionValue = prop.line;
            let sourceUsed = 'line';

            if (pythonPlayer) {
              const statKey = prop.prop_type;
              let pythonValue;
              if (statKey === 'points') pythonValue = pythonPlayer.points;
              else if (statKey === 'rebounds') pythonValue = pythonPlayer.rebounds;
              else if (statKey === 'assists') pythonValue = pythonPlayer.assists;

              if (pythonValue && pythonValue !== 0) {
                projectionValue = pythonValue;
                sourceUsed = 'python';
              } else {
                console.log(`⚠️ Python has zero for ${prop.player} (${statKey}), will try Tank01`);
              }
            }

            if (projectionValue === prop.line && matchedTank01) {
              const statKey = prop.prop_type;
              if (statKey === 'points') projectionValue = matchedTank01.points;
              else if (statKey === 'rebounds') projectionValue = matchedTank01.rebounds;
              else if (statKey === 'assists') projectionValue = matchedTank01.assists;
              sourceUsed = 'tank01';
            }

            if (projectionValue === undefined || projectionValue === null || isNaN(projectionValue)) {
              projectionValue = prop.line;
              sourceUsed = 'line';
            }

            // ----- Determine team -----
            const team = matchedTank01?.team || pythonPlayer?.team || 'UNKNOWN';

            // ----- Determine opponent (from game data) -----
            let opponent = 'TBD';
            if (team !== 'UNKNOWN' && prop.away_team_abbr && prop.home_team_abbr) {
              opponent = prop.away_team_abbr === team ? prop.home_team_abbr : (prop.home_team_abbr === team ? prop.away_team_abbr : 'TBD');
            }

            // ----- Opponent adjustment (only if opponent is known) -----
            if (team !== 'UNKNOWN' && opponent !== 'TBD') {
              let factor = 1.0;
              let factorSource = 'none';

              if (defensiveStatsMap.has(opponent)) {
                const oppStats = defensiveStatsMap.get(opponent);
                if (prop.prop_type === 'points') factor = oppStats.pointsAllowed / leagueAverages.points;
                else if (prop.prop_type === 'rebounds') factor = oppStats.reboundsAllowed / leagueAverages.rebounds;
                else if (prop.prop_type === 'assists') factor = oppStats.assistsAllowed / leagueAverages.assists;
                factorSource = 'tank01';
              } else if (DEFENSIVE_FACTORS[opponent]) {
                const staticFactor = DEFENSIVE_FACTORS[opponent];
                if (prop.prop_type === 'points') factor = staticFactor.points;
                else if (prop.prop_type === 'rebounds') factor = staticFactor.rebounds;
                else if (prop.prop_type === 'assists') factor = staticFactor.assists;
                factorSource = 'static';
              }

              if (factor !== 1.0) {
                projectionValue = projectionValue * factor;
                sourceUsed += `+opponent(${factorSource})`;
              }
            }

            const edge = prop.line > 0 ? ((projectionValue - prop.line) / prop.line) * 100 : 0;
            let confidence = 70;
            if (edge > 10) confidence = 85;
            else if (edge < -10) confidence = 55;

            return {
              id: `odds-${index}-${Date.now()}`,
              player: prop.player,
              team,
              opponent,
              sport: sport.toUpperCase(),
              position: matchedTank01?.position || pythonPlayer?.position || 'N/A',
              injury_status: matchedTank01?.injury_status || pythonPlayer?.injury_status || 'healthy',
              stat: prop.prop_type,
              line: prop.line,
              type: prop.type,
              projection: parseFloat(projectionValue.toFixed(1)),
              edge: edge.toFixed(1),
              confidence,
              odds: prop.odds ? `+${Math.round((prop.odds - 1) * 100)}` : '-110',
              timestamp: new Date().toISOString(),
              analysis: `${prop.player} ${prop.prop_type} – proj ${projectionValue.toFixed(1)} vs line ${prop.line}`,
              status: 'pending',
              source: 'the-odds-api',
              bookmaker: prop.bookmaker
            };
          });

          // Deduplicate by player+stat+line, keep highest odds
          const uniqueMap = new Map();
          selections.forEach(sel => {
            const key = `${sel.player}|${sel.stat}|${sel.line}`;
            const existing = uniqueMap.get(key);
            const oddsNum = typeof sel.odds === 'number' ? sel.odds : parseInt(sel.odds.replace('+', '')) || 0;
            const existingOddsNum = existing ? parseInt(existing.odds.replace('+', '')) || 0 : 0;
            if (!existing || oddsNum > existingOddsNum) {
              uniqueMap.set(key, sel);
            }
          });
          selections = Array.from(uniqueMap.values());
          console.log(`   🧹 After deduplication: ${selections.length} unique props`);

          source = 'the-odds-api+python';
        } catch (primaryError) {
          // ----- FALLBACK: Sport‑specific static data -----
          console.warn(`   ⚠️ Primary source failed for ${sport}, using sport‑specific static fallback:`, primaryError.message);

          let fallbackPlayers = staticPlayers;
          if (!fallbackPlayers || fallbackPlayers.length === 0) {
            fallbackPlayers = generateSportFallback(sport);
          }

          if (fallbackPlayers && fallbackPlayers.length > 0) {
            selections = fallbackPlayers.slice(0, 50).map((p, idx) => {
              const line = p.points;
              const projection = p.points;
              return {
                id: `fallback-${sport}-${idx}`,
                player: p.name,
                team: p.team || 'UNKNOWN',
                opponent: p.opponent || 'TBD',
                sport: sport.toUpperCase(),
                position: p.position || 'N/A',
                injury_status: p.injury_status || 'healthy',
                stat: 'points',
                line: parseFloat(line.toFixed(1)),
                type: 'over',
                projection: parseFloat(projection.toFixed(1)),
                edge: '0.0',
                confidence: 70,
                odds: '-110',
                timestamp: new Date().toISOString(),
                analysis: `Fallback based on ${sport} averages`,
                source: `${sport}-fallback`
              };
            });
            console.log(`   🔄 Generated ${selections.length} fallback props for ${sport}`);
            source = `${sport}-fallback`;
          } else {
            // ----- ULTIMATE FALLBACK: Very generic list -----
            selections = getGenericPlayersForSport(sport).map((p, idx) => ({
              id: `generic-${sport}-${idx}`,
              player: p.name,
              team: p.team,
              opponent: 'TBD',
              sport: sport.toUpperCase(),
              position: p.position,
              injury_status: 'healthy',
              stat: 'points',
              line: p.points,
              type: 'over',
              projection: p.points,
              edge: '0.0',
              confidence: 70,
              odds: '-110',
              timestamp: new Date().toISOString(),
              analysis: 'Generic fallback',
              source: 'generic'
            }));
            console.log(`   🆘 Generated ${selections.length} generic fallback props for ${sport}`);
            source = 'generic';
          }
        }

        const nonZeroEdge = selections.filter(s => parseFloat(s.edge) !== 0).length;
        console.log(`   📊 Edge stats: ${nonZeroEdge}/${selections.length} have non-zero edge`);

        return {
          success: true,
          message: `Player Props for ${sport.toUpperCase()}`,
          selections,
          count: selections.length,
          timestamp: new Date().toISOString(),
          source
        };
      },
      300 // cache TTL (seconds)
    );

    res.json(responsePayload);

  } catch (error) {
    console.error('❌ Fatal error in /api/prizepicks/selections:', error);

    // ----- EMERGENCY FALLBACK -----
    const sport = req.query.sport || 'nba';
    const genericPlayers = getGenericPlayersForSport(sport);
    const fallbackSelections = genericPlayers.map((player, idx) => ({
      id: `emergency-${sport}-${idx}`,
      player: player.name,
      team: player.team,
      opponent: 'TBD',
      sport: sport.toUpperCase(),
      position: player.position,
      injury_status: 'healthy',
      stat: 'points',
      line: player.points,
      type: 'over',
      projection: player.points,
      edge: '0.0',
      confidence: 70,
      odds: '-110',
      timestamp: new Date().toISOString(),
      analysis: 'Emergency fallback',
      source: 'emergency'
    }));

    res.json({
      success: true,
      message: 'Player Props (Emergency Fallback)',
      selections: fallbackSelections,
      count: fallbackSelections.length,
      timestamp: new Date().toISOString(),
      source: 'emergency'
    });
  }
});

// ========== ENHANCED FALLBACK GENERATOR WITH COMPLETE TEAMS ==========
function generateSportFallback(sport) {
  // Complete team lists for all four major sports
  const teamsBySport = {
    nba: [
      'ATL', 'BOS', 'BKN', 'CHA', 'CHI', 'CLE', 'DAL', 'DEN', 'DET', 'GSW',
      'HOU', 'IND', 'LAC', 'LAL', 'MEM', 'MIA', 'MIL', 'MIN', 'NOP', 'NYK',
      'OKC', 'ORL', 'PHI', 'PHX', 'POR', 'SAC', 'SAS', 'TOR', 'UTA', 'WAS'
    ],
    nhl: [
      'ANA', 'BOS', 'BUF', 'CGY', 'CAR', 'CHI', 'COL', 'CBJ', 'DAL', 'DET',
      'EDM', 'FLA', 'LAK', 'MIN', 'MTL', 'NSH', 'NJD', 'NYI', 'NYR', 'OTT',
      'PHI', 'PIT', 'SEA', 'SJS', 'STL', 'TBL', 'TOR', 'VAN', 'VGK', 'WPG',
      'WSH', 'UTA'
    ],
    mlb: [
      'ARI', 'ATL', 'BAL', 'BOS', 'CHC', 'CHW', 'CIN', 'CLE', 'COL', 'DET',
      'HOU', 'KC', 'LAA', 'LAD', 'MIA', 'MIL', 'MIN', 'NYM', 'NYY', 'OAK',
      'PHI', 'PIT', 'SD', 'SF', 'SEA', 'STL', 'TB', 'TEX', 'TOR', 'WSH'
    ],
    nfl: [
      'ARI', 'ATL', 'BAL', 'BUF', 'CAR', 'CHI', 'CIN', 'CLE', 'DAL', 'DEN',
      'DET', 'GB', 'HOU', 'IND', 'JAX', 'KC', 'LV', 'LAC', 'LAR', 'MIA',
      'MIN', 'NE', 'NO', 'NYG', 'NYJ', 'PHI', 'PIT', 'SF', 'SEA', 'TB',
      'TEN', 'WAS'
    ]
  };
  const teams = teamsBySport[sport] || teamsBySport.nba;

  // Player data combined from file1 and file2 (NHL extended with file2 additions)
  const players = {
    nba: [
      { name: 'LeBron James', team: 'LAL', position: 'SF', points: 27.5, injury_status: 'healthy' },
      { name: 'Stephen Curry', team: 'GSW', position: 'PG', points: 28.5, injury_status: 'healthy' },
      { name: 'Giannis Antetokounmpo', team: 'MIL', position: 'PF', points: 32.0, injury_status: 'healthy' },
      { name: 'Nikola Jokic', team: 'DEN', position: 'C', points: 26.5, injury_status: 'healthy' },
      { name: 'Luka Doncic', team: 'LAL', position: 'G', points: 28.8, injury_status: 'healthy' },
      { name: 'Shai Gilgeous-Alexander', team: 'OKC', position: 'G', points: 31.2, injury_status: 'healthy' },
      { name: 'Jayson Tatum', team: 'BOS', position: 'F', points: 27.5, injury_status: 'healthy' },
      { name: 'Jalen Johnson', team: 'ATL', position: 'F', points: 19.8, injury_status: 'healthy' },
      { name: 'Cade Cunningham', team: 'DET', position: 'G', points: 23.5, injury_status: 'healthy' },
      { name: 'Tyrese Maxey', team: 'PHI', position: 'G', points: 25.0, injury_status: 'healthy' },
      { name: 'Victor Wembanyama', team: 'SAS', position: 'C', points: 22.0, injury_status: 'healthy' },
      { name: 'Jaylen Brown', team: 'BOS', position: 'F', points: 23.5, injury_status: 'healthy' },
      { name: 'Jalen Brunson', team: 'NYK', position: 'G', points: 24.5, injury_status: 'healthy' },
      { name: 'Josh Giddey', team: 'CHI', position: 'G', points: 14.5, injury_status: 'healthy' },
      { name: 'Karl-Anthony Towns', team: 'NYK', position: 'C', points: 22.5, injury_status: 'healthy' },
      { name: 'Austin Reaves', team: 'LAL', position: 'G', points: 16.5, injury_status: 'healthy' },
      { name: 'Buddy Hield', team: 'ATL', position: 'G', points: 12.5, injury_status: 'healthy' },
      { name: 'Caleb Houstan', team: 'ATL', position: 'F', points: 6.5, injury_status: 'healthy' }
    ],
    nhl: [
      { name: 'Connor McDavid', team: 'EDM', position: 'C', points: 1.2, injury_status: 'healthy' },
      { name: 'Auston Matthews', team: 'TOR', position: 'C', points: 1.1, injury_status: 'healthy' },
      { name: 'Nathan MacKinnon', team: 'COL', position: 'C', points: 1.3, injury_status: 'healthy' },
      { name: 'Leon Draisaitl', team: 'EDM', position: 'C', points: 1.2, injury_status: 'healthy' },
      { name: 'David Pastrnak', team: 'BOS', position: 'RW', points: 1.0, injury_status: 'healthy' },
      { name: 'Nikita Kucherov', team: 'TBL', position: 'RW', points: 1.3, injury_status: 'healthy' },
      { name: 'Mikko Rantanen', team: 'COL', position: 'RW', points: 1.1, injury_status: 'healthy' },
      { name: 'Cale Makar', team: 'COL', position: 'D', points: 1.0, injury_status: 'healthy' },
      { name: 'Jack Hughes', team: 'NJD', position: 'C', points: 1.0, injury_status: 'healthy' },
      { name: 'Tage Thompson', team: 'BUF', position: 'C', points: 0.9, injury_status: 'healthy' }
    ],
    mlb: [
      { name: 'Shohei Ohtani', team: 'LAD', position: 'DH', points: 1.5, injury_status: 'healthy' },
      { name: 'Aaron Judge', team: 'NYY', position: 'RF', points: 1.4, injury_status: 'healthy' },
      { name: 'Mookie Betts', team: 'LAD', position: 'RF', points: 1.3, injury_status: 'healthy' },
      { name: 'Ronald Acuña Jr.', team: 'ATL', position: 'RF', points: 1.3, injury_status: 'healthy' },
      { name: 'Juan Soto', team: 'NYY', position: 'LF', points: 1.2, injury_status: 'healthy' },
      { name: 'Freddie Freeman', team: 'LAD', position: '1B', points: 1.2, injury_status: 'healthy' }
    ],
    nfl: [
      { name: 'Patrick Mahomes', team: 'KC', position: 'QB', points: 25.0, injury_status: 'healthy' },
      { name: 'Josh Allen', team: 'BUF', position: 'QB', points: 24.0, injury_status: 'healthy' },
      { name: 'Jalen Hurts', team: 'PHI', position: 'QB', points: 23.5, injury_status: 'healthy' },
      { name: 'Christian McCaffrey', team: 'SF', position: 'RB', points: 18.0, injury_status: 'healthy' },
      { name: 'Tyreek Hill', team: 'MIA', position: 'WR', points: 16.5, injury_status: 'healthy' },
      { name: 'Travis Kelce', team: 'KC', position: 'TE', points: 14.0, injury_status: 'healthy' }
    ]
  };

  const playerList = players[sport] || players.nba;

  return playerList.map((p, index) => {
    // Generate a random opponent different from player's team
    let opponent = 'TBD';
    if (teams.length > 0) {
      const possibleOpponents = teams.filter(t => t !== p.team);
      if (possibleOpponents.length > 0) {
        opponent = possibleOpponents[Math.floor(Math.random() * possibleOpponents.length)];
      }
    }

    return {
      id: `fallback-${sport}-${index}`,
      player: p.name,
      team: p.team,
      opponent: opponent,
      sport: sport.toUpperCase(),
      position: p.position,
      injury_status: p.injury_status,
      stat: 'points',
      line: p.points,
      type: 'over',
      projection: p.points,
      edge: '0.0',
      confidence: 70,
      odds: '-110',
      timestamp: new Date().toISOString(),
      analysis: `Fallback based on ${sport} averages`,
      source: `${sport}-fallback`
    };
  });
}

function getGenericPlayersForSport(sport) {
  return generateSportFallback(sport);
}

// Use your existing RapidAPI key from environment variables
const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY; 
const RAPIDAPI_HOST = 'tank01-nhl-live-in-game-real-time-statistics-nhl.p.rapidapi.com';

async function getTodaysNHLGames() {
  const cacheKey = `tank01:nhlGames:${new Date().toDateString()}`;
  
  try {
    return await getCachedOrFetch(
      cacheKey,
      async () => {
        // Format today's date as YYYYMMDD
        const today = new Date();
        const year = today.getFullYear();
        const month = String(today.getMonth() + 1).padStart(2, '0');
        const day = String(today.getDate()).padStart(2, '0');
        const gameDate = `${year}${month}${day}`;

        const url = `https://${RAPIDAPI_HOST}/getNHLGamesForDate?gameDate=${gameDate}`;
        
        const response = await fetch(url, {
          headers: {
            'x-rapidapi-host': RAPIDAPI_HOST,
            'x-rapidapi-key': RAPIDAPI_KEY
          }
        });

        if (!response.ok) {
          throw new Error(`Tank01 API responded with ${response.status}`);
        }

        const data = await response.json();
        
        // The API returns an array of games in the 'body' field
        const games = data.body || [];
        
        // Create a map of team -> opponent for today
        const opponentMap = new Map();
        games.forEach(game => {
          // game.away and game.home are the team abbreviations
          opponentMap.set(game.away, game.home);
          opponentMap.set(game.home, game.away);
        });

        return {
          games,
          opponentMap,
          teams: [...new Set([...games.map(g => g.away), ...games.map(g => g.home)])]
        };
      },
      3600 // Cache for 1 hour (games don't change often)
    );
  } catch (error) {
    console.error('Error fetching from Tank01 NHL:', error.message);
    // Return empty structure on failure – your existing fallback will still work
    return { games: [], opponentMap: new Map(), teams: [] };
  }
}

// Helper to get today's games from Sleeper (with fallback to Tank01)
async function getTodaysGamesFromSleeper(sport = 'nba') {
  const cacheKey = `sleeper:todaysGames:${sport}:${new Date().toDateString()}`;
  
  try {
    return await getCachedOrFetch(
      cacheKey,
      async () => {
        const sportCode = sport === 'nba' ? 'nba' : sport === 'nfl' ? 'nfl' : sport;
        const today = new Date();
        
        const response = await fetch(`https://api.sleeper.app/v1/schedule/${sportCode}/regular/${today.getFullYear()}?week=${getCurrentWeek()}`);

        if (!response.ok) {
          throw new Error(`Sleeper API responded with ${response.status}`);
        }

        const schedule = await response.json();

        const todaysGames = Array.isArray(schedule) ? schedule.filter(game => {
          const gameDate = new Date(game.game_date);
          return gameDate.toDateString() === today.toDateString();
        }) : [];

        const playerIds = new Set();
        if (Array.isArray(todaysGames)) {
          todaysGames.forEach(game => {
            if (game.away_players && Array.isArray(game.away_players)) {
              game.away_players.forEach(id => playerIds.add(id));
            }
            if (game.home_players && Array.isArray(game.home_players)) {
              game.home_players.forEach(id => playerIds.add(id));
            }
          });
        }

        const teamsSet = new Set();
        if (Array.isArray(todaysGames)) {
          todaysGames.forEach(game => {
            if (game.away_team) teamsSet.add(game.away_team);
            if (game.home_team) teamsSet.add(game.home_team);
          });
        }

        return {
          games: todaysGames,
          playerIds: Array.from(playerIds),
          gameIds: Array.isArray(todaysGames) ? todaysGames.map(g => g.game_id).filter(id => id) : [],
          teams: Array.from(teamsSet)
        };
      },
      3600
    );
  } catch (error) {
    console.error('Error fetching from Sleeper:', error.message);
    
    // Fallback: day-specific team lists
    const today = new Date();
    const dayOfWeek = today.getDay();
    
    const teamsPlayingToday = {
      'nba': {
        0: ['LAL', 'GSW', 'BOS', 'NYK', 'MIA', 'CHI'],
        1: ['MIL', 'PHX', 'DAL', 'DEN', 'LAC', 'POR'],
        2: ['LAL', 'GSW', 'BOS', 'PHI', 'MEM', 'SAS'],
        3: ['MIL', 'PHX', 'DAL', 'DEN', 'UTA', 'NOP'],
        4: ['LAL', 'GSW', 'BOS', 'NYK', 'ATL', 'HOU'],
        5: ['MIL', 'PHX', 'DAL', 'DEN', 'LAC', 'MEM', 'GSW', 'LAL'],
        6: ['LAL', 'GSW', 'BOS', 'PHI', 'MIA', 'ATL', 'CHI', 'CLE']
      },
      'nfl': [],
      'nhl': [],
      'mlb': []
    };
    
    const defaultTeams = ['LAL', 'GSW', 'BOS', 'MIL', 'PHX', 'DEN', 'DAL', 'PHI', 'MIA', 'LAC'];
    const teamsForDay = teamsPlayingToday[sport] && teamsPlayingToday[sport][dayOfWeek] 
      ? teamsPlayingToday[sport][dayOfWeek] 
      : defaultTeams;
    
    return {
      games: [],
      playerIds: [],
      gameIds: [],
      teams: teamsForDay
    };
  }
}

// ============================================================
// Unified Fantasy Hub Players Endpoint
// ============================================================
app.get('/api/fantasyhub/players', async (req, res) => {
  console.log('🏀 [FantasyHub Endpoint] Request for players');
  const { sport = 'nba', filterByToday = 'true' } = req.query;
  const cacheKey = `fantasyhub:players:${sport}:${filterByToday}:${new Date().toDateString()}`;

  // Tank01 to standard abbreviation mapping (for filtering)
  const TANK01_TO_STD = {
    'NY': 'NYK',
    'SA': 'SAS',
    'NO': 'NOP',
    'PHO': 'PHX',
    'GS': 'GSW',
    'UTH': 'UTA',
  };
  
  try {
    const responseData = await getCachedOrFetch(
      cacheKey,
      async () => {
        // Get today's games from Sleeper
        let todaysGameInfo = { games: [], playerIds: [], teams: [] };
        try {
          todaysGameInfo = await getTodaysGamesFromSleeper(sport);
          console.log(`   📅 Found ${todaysGameInfo.games.length} games today from Sleeper`);
          if (todaysGameInfo.teams.length > 0) {
            console.log(`   📅 Teams playing today (raw): ${todaysGameInfo.teams.join(', ')}`);
          }  
        } catch (error) {
          console.warn('   ⚠️ Could not fetch today\'s games from Sleeper:', error.message);
        }

        // If Sleeper gave no games, try Tank01
        if (todaysGameInfo.games.length === 0) {
          try {
            const today = new Date();
            const year = today.getFullYear();
            const month = String(today.getMonth() + 1).padStart(2, '0');
            const day = String(today.getDate()).padStart(2, '0');
            const todayStr = `${year}${month}${day}`;
            
            const tank01Games = await getCachedTank01Data('getGamesForDate', {
              gameDate: todayStr,
              sport
            }, 300);
            
            if (tank01Games && tank01Games.length > 0) {
              todaysGameInfo.games = tank01Games;
              todaysGameInfo.teams = [];
              tank01Games.forEach(game => {
                if (game.away) todaysGameInfo.teams.push(game.away);
                if (game.home) todaysGameInfo.teams.push(game.home);
              });
              console.log(`   📅 Found ${tank01Games.length} games from Tank01`);
            }
          } catch (tankErr) {
            console.warn('   ⚠️ Tank01 games also failed:', tankErr.message);
          }
        }

        // Convert team abbreviations to standard format for filtering
        const standardTeams = todaysGameInfo.teams.map(t => TANK01_TO_STD[t] || t);
        console.log(`   📅 Teams playing today (standardized): ${standardTeams.join(', ')}`);

        // Build opponent map from games
        const opponentMap = new Map();
        if (todaysGameInfo.games && todaysGameInfo.games.length > 0) {
          todaysGameInfo.games.forEach(game => {
            const away = game.away_team || game.away;
            const home = game.home_team || game.home;
            if (away && home) {
              opponentMap.set(away, home);
              opponentMap.set(home, away);
            }
          });
        }

        // Fetch defensive stats (only for NBA)
        let defensiveStatsMap = new Map();
        let leagueAverages = { points: 110, rebounds: 42, assists: 24 };
        if (sport === 'nba') {
          try {
            defensiveStatsMap = await fetchTeamDefensiveStats(sport);
            if (defensiveStatsMap.size > 0) {
              leagueAverages = computeLeagueAverages(defensiveStatsMap);
            }
            console.log(`   ✅ Fetched defensive stats for ${defensiveStatsMap.size} NBA teams`);
          } catch (defError) {
            console.warn('   ⚠️ Could not fetch defensive stats, opponent adjustment will be skipped:', defError.message);
          }
        } else {
          console.log(`   ℹ️ Defensive stats not fetched for ${sport} (NBA only)`);
        }

// In the MLB/NHL section of your /api/fantasyhub/players endpoint
if (sport === 'mlb' || sport === 'nhl') {
  try {
    let staticPlayers = sport === 'mlb' ? staticMLBPlayers : staticNHLPlayers;
    
    if (!staticPlayers || staticPlayers.length === 0) {
      throw new Error(`No static data available for ${sport}`);
    }

    console.log(`   ✅ Using static ${sport.toUpperCase()} data (${staticPlayers.length} players)`);

    // Transform to match frontend expectations with enhanced stats
    const transformed = staticPlayers.map(p => {
      // Base stats always present
      const player = {
        player_id: p.id,
        name: p.name,
        team: p.team,
        position: p.position,
        points: p.points || 0,
        rebounds: sport === 'mlb' ? 0 : (p.rebounds || 0),
        assists: p.assists || 0,
        salary: p.salary || 5000,
        injury_status: p.injury_status || 'Healthy',
        games_played: p.games_played || 0,
        source: 'static_python'
      };

      // Calculate fantasy points if not provided
      let fantasyPoints = p.fantasy_points || p.projection || 0;
      if (fantasyPoints === 0) {
        if (sport === 'nhl') {
          // NHL fantasy calculation: goals (3) + assists (2) + shots (0.5) + hits (0.5) + blocks (1)
          fantasyPoints = (p.goals || 0) * 3 + 
                         (p.assists || 0) * 2 + 
                         (p.shots || 0) * 0.5 + 
                         (p.hits || 0) * 0.5 + 
                         (p.blockedShots || 0) * 1;
        } else if (sport === 'mlb') {
          // MLB fantasy calculation (customize based on your league settings)
          fantasyPoints = (p.points || 0) + (p.rbi || 0) * 0.5;
        }
      }
      
      player.fantasy_points = fantasyPoints;
      player.projection = fantasyPoints; // For frontend Proj column

      // Add NHL-specific enhanced stats if available
      if (sport === 'nhl') {
        // Core counting stats
        player.goals = p.goals || 0;
        player.assists = p.assists || 0; // Already set above
        player.points = p.points || 0; // Already set above as 'points'
        player.plusMinus = p.plusMinus || 0;
        player.shots = p.shots || 0;
        player.hits = p.hits || 0;
        player.blockedShots = p.blockedShots || 0;
        
        // Ice time
        player.timeOnIce = p.timeOnIce || '0:00';
        player.powerPlayTimeOnIce = p.powerPlayTimeOnIce || '0:00';
        player.shortHandedTimeOnIce = p.shortHandedTimeOnIce || '0:00';
        
        // Power play stats
        player.powerPlayGoals = p.powerPlayGoals || 0;
        player.powerPlayAssists = p.powerPlayAssists || 0;
        player.powerPlayPoints = p.powerPlayPoints || 0;
        
        // Faceoffs
        player.faceoffsWon = p.faceoffsWon || 0;
        player.faceoffsLost = p.faceoffsLost || 0;
        player.faceoffs = p.faceoffs || 0;
        player.faceoffPercent = p.faceoffs ? ((p.faceoffsWon || 0) / p.faceoffs * 100).toFixed(1) : 0;
        
        // Penalties
        player.penalties = p.penalties || 0;
        player.penaltiesInMinutes = p.penaltiesInMinutes || 0;
        
        // Other
        player.shifts = p.shifts || 0;
        player.takeaways = p.takeaways || 0;
        player.giveaways = p.giveaways || 0;
        player.shotsMissedNet = p.shotsMissedNet || 0;
      } else if (sport === 'mlb') {
        // MLB-specific stats (add based on your needs)
        player.atBats = p.atBats || 0;
        player.hits = p.hits || 0;
        player.homeRuns = p.homeRuns || 0;
        player.rbi = p.rbi || 0;
        player.stolenBases = p.stolenBases || 0;
        player.battingAverage = p.battingAverage || 0;
        player.onBasePercentage = p.onBasePercentage || 0;
        player.sluggingPercentage = p.sluggingPercentage || 0;
        player.ops = p.ops || 0;
        
        // Pitching stats
        player.inningsPitched = p.inningsPitched || 0;
        player.era = p.era || 0;
        player.whip = p.whip || 0;
        player.strikeouts = p.strikeouts || 0;
        player.wins = p.wins || 0;
        player.losses = p.losses || 0;
        player.saves = p.saves || 0;
      }

      return player;
    });

    // Apply today's games filter if needed
    let filteredPlayers = transformed;
    if (filterByToday === 'true' && standardTeams.length > 0) {
      const beforeCount = filteredPlayers.length;
      filteredPlayers = filteredPlayers.filter(p => 
        p.team && standardTeams.includes(p.team)
      );
      console.log(`   🎯 Filtered from ${beforeCount} to ${filteredPlayers.length} players from today's games`);
    }

    // Return the data (will be cached by getCachedOrFetch)
    return {
      data: filteredPlayers,
      count: filteredPlayers.length,
      source: 'static_python',
      games_today: todaysGameInfo.games ? todaysGameInfo.games.length : 0,
      teams_today: standardTeams
    };

  } catch (staticError) {
    console.error(`   ❌ Static data fetch failed for ${sport}:`, staticError.message);

            // 🔁 FALLBACK: generate mock players
            console.log(`   ⚠️ Generating mock ${sport.toUpperCase()} players as fallback`);

            const fallbackTeams = (sport === 'mlb')
              ? ['ARI','ATL','BAL','BOS','CHC','CWS','CIN','CLE','COL','DET',
                 'HOU','KC','LAA','LAD','MIA','MIL','MIN','NYM','NYY','OAK',
                 'PHI','PIT','SD','SF','SEA','STL','TB','TEX','TOR','WSH']
              : ['ANA','ARI','BOS','BUF','CAR','CBJ','CGY','CHI','COL','DAL',
                 'DET','EDM','FLA','LAK','MIN','MTL','NJD','NSH','NYI','NYR',
                 'OTT','PHI','PIT','SEA','SJS','STL','TBL','TOR','VAN','VGK',
                 'WPG','WSH'];

            const positions = sport === 'mlb'
              ? ['P','C','1B','2B','3B','SS','LF','CF','RF','DH']
              : ['C','LW','RW','D','G'];

            const mockPlayers = [];

            fallbackTeams.forEach((teamAbbr, teamIdx) => {
              const numPlayers = 15 + Math.floor(Math.random() * 10);
              for (let i = 0; i < numPlayers; i++) {
                const salary = 4000 + Math.floor(Math.random() * 9000);
                const points = sport === 'nhl' ? 0.5 + Math.random() * 1.5 : 5 + Math.random() * 20;
                const rebounds = sport === 'mlb' ? 0 : (2 + Math.random() * 8);
                const assists = 1 + Math.random() * 7;
                const fantasy = points + rebounds * 0.8 + assists * 0.8;

                mockPlayers.push({
                  player_id: `mock-${sport}-${teamAbbr}-${i}`,
                  name: `${sport.toUpperCase()} Player ${teamIdx * 100 + i}`,
                  team: teamAbbr,
                  position: positions[i % positions.length],
                  points: parseFloat(points.toFixed(1)),
                  rebounds: parseFloat(rebounds.toFixed(1)),
                  assists: parseFloat(assists.toFixed(1)),
                  fantasy_points: parseFloat(fantasy.toFixed(1)),
                  salary,
                  injury_status: Math.random() > 0.9 ? 'Day-to-Day' : 'Healthy',
                  source: 'mock'
                });
              }
            });

            let filteredMock = mockPlayers;
            if (filterByToday === 'true' && standardTeams.length > 0) {
              filteredMock = mockPlayers.filter(p => standardTeams.includes(p.team));
            }

            return {
              data: filteredMock,
              count: filteredMock.length,
              source: 'mock-fallback',
              games_today: todaysGameInfo.games ? todaysGameInfo.games.length : 0,
              teams_today: standardTeams
            };
          }
        }

        // ========== NBA: Use Node master API with retry logic ==========
        let players = null;
        let nodeError = null;
        const maxRetries = 3;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
          try {
            const nodeMasterUrl = `https://prizepicks-production.up.railway.app/api/players/master?sport=${sport}`;
            console.log(`   🔄 Fetching from Node master (attempt ${attempt}/${maxRetries}): ${nodeMasterUrl}`);
            
            const response = await fetch(nodeMasterUrl);
            
            if (!response.ok) {
              if (response.status === 429 && attempt < maxRetries) {
                const delay = Math.pow(2, attempt) * 1000;
                console.log(`   ⏳ Rate limited, waiting ${delay}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                continue;
              }
              throw new Error(`Node master HTTP ${response.status}`);
            }
            
            const result = await response.json();
            if (!result.success || !Array.isArray(result.data)) {
              throw new Error('Node master returned invalid data');
            }

            let transformedPlayers = result.data.map(p => ({
              player_id: p.id,
              name: p.name,
              team: p.team,
              position: p.position,
              injury_status: p.injury_status || 'Healthy',
              points: p.points || 0,
              rebounds: p.rebounds || 0,
              assists: p.assists || 0,
              steals: p.steals || 0,
              blocks: p.blocks || 0,
              turnovers: p.turnovers || 0,
              fantasy_points: p.projection || p.fantasy_points || 0,
              salary: p.salary || 5000,
              games_played: p.games_played || 0,
              adp: p.adp,
              is_rookie: p.is_rookie || false,
              value: p.salary ? ((p.projection || 0) / p.salary) * 1000 : 0,
              source: 'node_master'
            }));
            
            // Filter by today's games using standardized team abbreviations
            if (filterByToday === 'true' && standardTeams.length > 0) {
              const beforeCount = transformedPlayers.length;
              transformedPlayers = transformedPlayers.filter(p =>   
                p.team && standardTeams.includes(p.team)
              );
              console.log(`   🎯 Filtered from ${beforeCount} to ${transformedPlayers.length} players from today's games (standardized teams)`);
            }

            // Opponent adjustment (real stats + static fallback) - NBA only
            transformedPlayers = transformedPlayers.map(p => {
              const opponent = opponentMap.get(p.team);
              if (opponent) {
                if (defensiveStatsMap.has(opponent)) {
                  const oppStats = defensiveStatsMap.get(opponent);
                  
                  p.original_points = p.points;
                  p.original_rebounds = p.rebounds;
                  p.original_assists = p.assists;

                  const pointsFactor = oppStats.pointsAllowed / leagueAverages.points;
                  const reboundsFactor = oppStats.reboundsAllowed / leagueAverages.rebounds;
                  const assistsFactor = oppStats.assistsAllowed / leagueAverages.assists;

                  p.points *= pointsFactor;
                  p.rebounds *= reboundsFactor;
                  p.assists *= assistsFactor;

                  p.fantasy_points = (
                    p.points +
                    1.2 * p.rebounds +
                    1.5 * p.assists +
                    2 * (p.steals || 0) +
                    2 * (p.blocks || 0) -
                    (p.turnovers || 0)
                  );

                  p.matchup_opponent = opponent;
                  p.matchup_factors = {
                    points: pointsFactor,
                    rebounds: reboundsFactor,
                    assists: assistsFactor,
                    source: 'tank01'
                  };

                  console.log(`   Adjustment for ${p.name} (${p.team}) vs ${opponent} (Tank01): factors pts=${pointsFactor.toFixed(2)}, reb=${reboundsFactor.toFixed(2)}, ast=${assistsFactor.toFixed(2)} → new FP ${p.fantasy_points.toFixed(1)}`);
                }
                else if (DEFENSIVE_FACTORS[opponent]) {
                  const staticFactor = DEFENSIVE_FACTORS[opponent];
                  
                  p.original_points = p.points;
                  p.original_rebounds = p.rebounds;
                  p.original_assists = p.assists;

                  p.points *= staticFactor.points;
                  p.rebounds *= staticFactor.rebounds;
                  p.assists *= staticFactor.assists;

                  p.fantasy_points = (
                    p.points +
                    1.2 * p.rebounds +
                    1.5 * p.assists +
                    2 * (p.steals || 0) +
                    2 * (p.blocks || 0) -
                    (p.turnovers || 0)
                  );

                  p.matchup_opponent = opponent;
                  p.matchup_factors = {
                    points: staticFactor.points,
                    rebounds: staticFactor.rebounds,
                    assists: staticFactor.assists,
                    source: 'static'
                  };

                  console.log(`   Adjustment for ${p.name} (${p.team}) vs ${opponent} (static): factors pts=${staticFactor.points.toFixed(2)}, reb=${staticFactor.rebounds.toFixed(2)}, ast=${staticFactor.assists.toFixed(2)} → new FP ${p.fantasy_points.toFixed(1)}`);
                } else {
                  console.log(`   No defensive stats or static factors for opponent ${opponent}, skipping adjustment for ${p.name}`);
                }
              }
              return p;
            });
               
            players = transformedPlayers;
            break;
          } catch (err) {
            nodeError = err;
            if (attempt === maxRetries) {
              console.error('❌ Node master fetch failed after retries:', err.message);
            }
          }
        }
            
        if (players) {
          return {
            data: players,
            count: players.length,
            source: 'node_master',
            games_today: todaysGameInfo.games ? todaysGameInfo.games.length : 0,
            teams_today: standardTeams
          };
        }
              
        // Fallback: static NBA players with filtering
        console.warn('❌ Using fallback player data due to:', nodeError?.message || 'unknown error');
        try {
          let basePlayers = [];
            
          if (staticNBAPlayers.length > 0) {
            basePlayers = staticNBAPlayers.map(p => ({
              player_id: p.id || `static-${p.name.replace(/\s+/g, '_')}`,
              name: p.name,
              team: p.team,
              position: p.position,
              injury_status: p.injury_status || 'healthy',
              points: p.points || 0,
              rebounds: p.rebounds || 0,
              assists: p.assists || 0,
              steals: p.steals || 0,
              blocks: p.blocks || 0,
              turnovers: p.turnovers || 0,
              fantasy_points: p.fantasy_points || p.projection || 0,
              salary: p.salary || 5000,
              games_played: p.games_played || 0,
              is_real_data: true,
              source: 'static_2026'
            }));
          } else {
            console.log('   ⚠️ No static players, using generated fallback');
            basePlayers = generateIntelligentFantasyFallback(sport);
          }
          
          // Filter by today's games using standardized team abbreviations
          if (filterByToday === 'true' && standardTeams.length > 0) {
            const beforeCount = basePlayers.length;
            basePlayers = basePlayers.filter(p =>
              p.team && standardTeams.includes(p.team)
            );
            console.log(`   🎯 Filtered fallback from ${beforeCount} to ${basePlayers.length} players from today's games (standardized teams)`);
          }  
         
          let tank01Master = new Map();
          try {
            tank01Master = await getTank01MasterData(sport);
            console.log(`   ✅ Fetched Tank01 master data with ${tank01Master.size} entries for enrichment`);
          } catch (e) {
            console.warn('   ⚠️ Could not fetch Tank01 master data, continuing with static only');
          }
              
          let enrichedPlayers = basePlayers.map(player => {
            let enriched = { ...player, enriched: false, source: player.source };
              
            if (tank01Master.size > 0) {
              // enrichment logic (if any) would go here
            }
              
            if (enriched.salary > 0) {
              enriched.value = ((enriched.fantasy_points || 0) / enriched.salary) * 1000;
            } else {
              enriched.value = 0;
            }
          
            return enriched;
          });

          // Opponent adjustment for enriched players (real stats + static fallback)
          enrichedPlayers = enrichedPlayers.map(p => {
            const opponent = opponentMap.get(p.team);
            if (opponent) {
              if (defensiveStatsMap.has(opponent)) {
                const oppStats = defensiveStatsMap.get(opponent);
                
                p.original_points = p.points;
                p.original_rebounds = p.rebounds;
                p.original_assists = p.assists;

                const pointsFactor = oppStats.pointsAllowed / leagueAverages.points;
                const reboundsFactor = oppStats.reboundsAllowed / leagueAverages.rebounds;
                const assistsFactor = oppStats.assistsAllowed / leagueAverages.assists;

                p.points *= pointsFactor;
                p.rebounds *= reboundsFactor;
                p.assists *= assistsFactor;

                p.fantasy_points = (
                  p.points +
                  1.2 * p.rebounds +
                  1.5 * p.assists +
                  2 * (p.steals || 0) +
                  2 * (p.blocks || 0) -
                  (p.turnovers || 0)
                );

                p.matchup_opponent = opponent;
                p.matchup_factors = {
                  points: pointsFactor,
                  rebounds: reboundsFactor,
                  assists: assistsFactor,
                  source: 'tank01'
                };

                console.log(`   Adjustment for ${p.name} (${p.team}) vs ${opponent} (Tank01): factors pts=${pointsFactor.toFixed(2)}, reb=${reboundsFactor.toFixed(2)}, ast=${assistsFactor.toFixed(2)} → new FP ${p.fantasy_points.toFixed(1)}`);
              }
              else if (DEFENSIVE_FACTORS[opponent]) {
                const staticFactor = DEFENSIVE_FACTORS[opponent];
                
                p.original_points = p.points;
                p.original_rebounds = p.rebounds;
                p.original_assists = p.assists;

                p.points *= staticFactor.points;
                p.rebounds *= staticFactor.rebounds;
                p.assists *= staticFactor.assists;

                p.fantasy_points = (
                  p.points +
                  1.2 * p.rebounds +
                  1.5 * p.assists +
                  2 * (p.steals || 0) +
                  2 * (p.blocks || 0) -
                  (p.turnovers || 0)
                );

                p.matchup_opponent = opponent;
                p.matchup_factors = {
                  points: staticFactor.points,
                  rebounds: staticFactor.rebounds,
                  assists: staticFactor.assists,
                  source: 'static'
                };

                console.log(`   Adjustment for ${p.name} (${p.team}) vs ${opponent} (static): factors pts=${staticFactor.points.toFixed(2)}, reb=${staticFactor.rebounds.toFixed(2)}, ast=${staticFactor.assists.toFixed(2)} → new FP ${p.fantasy_points.toFixed(1)}`);
              } else {
                console.log(`   No defensive stats or static factors for opponent ${opponent}, skipping adjustment for ${p.name}`);
              }
            }
            return p;
          });
            
          console.log(`   ✅ Enriched ${enrichedPlayers.filter(p => p.enriched).length}/${enrichedPlayers.length} players`);   
          return {
            data: enrichedPlayers,
            count: enrichedPlayers.length,
            stats: {
              total: enrichedPlayers.length,
              enriched: enrichedPlayers.filter(p => p.enriched).length,
              source: staticNBAPlayers.length ? 'static_2026' : 'fallback'
            },
            games_today: todaysGameInfo.games ? todaysGameInfo.games.length : 0,
            teams_today: standardTeams
          };       
        } catch (fallbackError) {
          console.error('❌ FantasyHub fallback error:', fallbackError);
          const fallbackPlayers = generateIntelligentFantasyFallback(sport); 
                    
          if (filterByToday === 'true' && standardTeams.length > 0) {
            const filteredFallback = fallbackPlayers.filter(p =>
              p.team && standardTeams.includes(p.team)
            );
            return {
              message: 'Fantasy Hub Analysis (Fallback Mode)',
              data: filteredFallback.length > 0 ? filteredFallback : fallbackPlayers,
              count: filteredFallback.length > 0 ? filteredFallback.length : fallbackPlayers.length,
              source: 'fallback',
              note: fallbackError.message,
              games_today: todaysGameInfo.games ? todaysGameInfo.games.length : 0
            };
          }
             
          return {
            message: 'Fantasy Hub Analysis (Fallback Mode)',
            data: fallbackPlayers,
            count: fallbackPlayers.length,
            source: 'fallback',   
            note: fallbackError.message   
          };
        }
      },
      300
    );

    return res.json({
      success: true,
      cached: true,
      ...responseData
    });

  } catch (error) {
    console.error('❌ FantasyHub endpoint error:', error);
    const fallbackPlayers = generateIntelligentFantasyFallback(sport);
    return res.json({
      success: true,
      message: 'Fantasy Hub Analysis (Emergency Fallback)',
      data: fallbackPlayers,
      count: fallbackPlayers.length,
      timestamp: new Date().toISOString(),
      source: 'emergency_fallback',
      note: error.message
    });
  }
});

// ====================
// DIRECT THE ODDS API ENDPOINT
// ====================
app.get('/api/theoddsapi/playerprops', async (req, res) => {
  const sport = req.query.sport || 'basketball_nba';
  const cacheKey = `oddsapi:playerprops:${sport}`;
  
  try {
    const response = await getCachedOrFetch(
      cacheKey,
      async () => {
        const playerProps = await fetchPlayerPropsFromOddsAPI(sport);
        const enrichedProps = playerProps.map(prop => {
          const staticPlayer = findStaticPlayer(prop.player);
          return {
            ...prop,
            player_team: staticPlayer?.team,
            player_position: staticPlayer?.position,
            injury_status: staticPlayer?.injury_status
          };
        });

        return {
          success: true,
          count: enrichedProps.length,
          source: 'the-odds-api+static',
          data: enrichedProps,
          retrieved: new Date().toISOString()
        };
      },
      300
    );
    
    res.json(response);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, data: [] });
  }
});

// ====================
// DRAFT ENDPOINTS
// ====================
async function getEnrichedPlayers(sport = 'nba') {
  const cacheKey = `draft:enriched:v5:${sport}`;
  
  return await getCachedOrFetch(
    cacheKey,
    async () => {
      let rawPlayers = [];

      // ----- For NBA: use static 2026 data as base -----
      if (sport === 'nba' && staticNBAPlayers.length > 0) {
        console.log(`   [getEnrichedPlayers] Using static NBA players (${staticNBAPlayers.length}) as base`);

        // Fetch Tank01 master data for ADP and injury enrichment
        let tank01Master = new Map();
        try {
          tank01Master = await getTank01MasterData(sport);
          console.log(`   Tank01 master has ${tank01Master.size} entries for enrichment`);
        } catch (error) {
          console.warn('   Could not fetch Tank01 master, ADP/injury may be missing');
        }

        // Normalize name for matching
        const normalizeName = (name) => name.replace(/[.\s'\-]/g, '').toLowerCase();

        // Build a map from normalized Tank01 name to player data
        const tank01ByName = new Map();
        for (const [id, p] of tank01Master.entries()) {
          if (p.name) {
            const norm = normalizeName(p.name);
            tank01ByName.set(norm, p);
          }
        }

        // Map static players, enriching with ADP/injury from Tank01
        rawPlayers = staticNBAPlayers.map(p => {
          const normStatic = normalizeName(p.name);
          const tank01Match = tank01ByName.get(normStatic);

          const projection = p.fantasy_points || p.points || 0;

          return {
            playerId: p.id || `static-${p.name.replace(/\s+/g, '_')}`,
            name: p.name,
            team: p.team,
            position: p.position,
            salary: 5000, // temporary, will be scaled
            projection,
            value: 0,
            injury_status: tank01Match?.injury_status || p.injury_status || 'Healthy',
            volatility: (tank01Match?.injury_status === 'Injured' || p.injury_status === 'Injured') ? 0.15 : 0.08,
            is_rookie: p.is_rookie || false,
            adp: tank01Match?.adp || p.adp || 999
          };
        });

        console.log(`   Enriched ${rawPlayers.length} static players with Tank01 data`);
      } else {
        // ----- For other sports, use Tank01 master data as primary (with fallback) -----
        // (existing code – unchanged)
        try {
          console.log(`   [getEnrichedPlayers] Attempting Tank01 master for ${sport}...`);
          const tank01Master = await getTank01MasterData(sport);
          if (tank01Master.size > 0) {
            console.log(`   Tank01 master has ${tank01Master.size} entries`);
            rawPlayers = Array.from(tank01Master.values()).map(p => ({
              playerId: p.playerID || `${sport}-${p.name.replace(/\s+/g, '-')}`,
              name: p.name,
              team: p.team,
              position: p.position,
              salary: 5000, // temporary
              projection: p.projection || 0,
              value: 0,
              injury_status: p.injury_status || 'Healthy',
              volatility: p.injury_status === 'Healthy' ? 0.08 : 0.15,
              is_rookie: false,
              adp: p.adp || 999
            }));
            console.log(`   Mapped ${rawPlayers.length} players from Tank01`);
          } else {
            throw new Error('Tank01 master map is empty');
          }
        } catch (error) {
          console.warn(`   Tank01 master failed for ${sport}, falling back to static:`, error.message);

          let staticArray = [];
          if (sport === 'nhl') staticArray = staticNHLPlayers;
          else if (sport === 'mlb') staticArray = staticMLBPlayers;
          else if (sport === 'nfl') staticArray = staticNFLPlayers;

          if (staticArray.length > 0) {
            rawPlayers = staticArray.map(p => ({
              playerId: p.id || `static-${p.name.replace(/\s+/g, '_')}`,
              name: p.name || 'Unknown',
              team: p.team || 'FA',
              position: p.position || 'N/A',
              salary: p.salary || 5000,
              projection: p.points || p.projection || 20,
              value: p.value || ((p.points || 20) / (p.salary || 5000)) * 1000,
              injury_status: p.injury_status || 'Healthy',
              volatility: p.injury_status === 'Healthy' ? 0.08 : 0.15,
              is_rookie: p.is_rookie || false,
              adp: p.adp || 999
            }));
          } else {
            // Final fallback: generated players for the sport
            console.log(`   Using generated fallback for ${sport}`);
            const fallback = generateSportFallback(sport);
            rawPlayers = fallback.map(p => ({
              playerId: p.player_id || `fallback-${p.name.replace(/\s+/g, '_')}`,
              name: p.name,
              team: p.team,
              position: p.position,
              salary: p.salary || 7000,
              projection: typeof p.projection === 'object' ? p.projection.line : (p.projection || 20),
              value: p.value || ((typeof p.projection === 'object' ? p.projection.line : 20) / (p.salary || 7000)) * 1000,
              injury_status: p.injury_status || 'Healthy',
              volatility: 0.1 + Math.random() * 0.1,
              adp: 999
            }));
          }
        }
      }

      // ----- Deduplicate by playerId (keep highest salary) -----
      const uniqueMap = new Map();
      rawPlayers.forEach(p => {
        if (!uniqueMap.has(p.playerId) || p.salary > (uniqueMap.get(p.playerId).salary || 0)) {
          uniqueMap.set(p.playerId, p);
        }
      });
      let basePlayers = Array.from(uniqueMap.values());

// ----- Apply percentile‑based salary scaling (UPDATED FOR NBA) -----
if (basePlayers.length > 0) {
  const projections = basePlayers.map(p => p.projection).filter(v => v > 0);
  if (projections.length > 0) {
    const minProj = Math.min(...projections);
    const maxProj = Math.max(...projections);
    const minSalary = 3500;                     // raised from 3000
    let maxSalary = 15000; // default for other sports
    if (sport === 'nba') {
      maxSalary = 12000;                         // FanDuel‑style top salary
    } else if (sport === 'nfl') {
      maxSalary = 18000;
    }
    // NHL and MLB keep default 15000 (adjust later if needed)

    basePlayers.forEach(p => {
      if (p.projection > 0) {
        const ratio = (p.projection - minProj) / (maxProj - minProj);
        p.salary = Math.round(minSalary + ratio * (maxSalary - minSalary));
      } else {
        p.salary = minSalary;
      }
      p.value = p.projection > 0 ? (p.projection / p.salary) * 1000 : 0;
    });
  }
}

      console.log(`   [getEnrichedPlayers] Final count: ${basePlayers.length} unique players`);
      console.log(`   Sample:`, basePlayers.slice(0, 3).map(p => p.name));
      return basePlayers;
    },
    300
  );
}

app.get('/api/draft/rankings', async (req, res) => {
  try {
    console.log('📊 Draft rankings query:', req.query);
    const { sport = 'nba', position, limit = 50, pick, strategy = 'balanced' } = req.query;

    const cacheKey = `draft:rankings:${sport}:${position || 'all'}:${limit}:${pick || 'none'}:${strategy}`;

    const response = await getCachedOrFetch(
      cacheKey,
      async () => {
        // ----- Get today's games from Tank01 -----
        const today = new Date().toISOString().slice(0,10).replace(/-/g, '');
        let games = [];
        try {
          games = await getCachedTank01Data('getGamesForDate', { gameDate: today }, 300);
          console.log(`   Raw games from Tank01: ${games?.length || 0} games`);
        } catch (error) {
          console.warn('⚠️ Could not fetch today\'s games:', error.message);
        }

        const teamsPlayingToday = new Set();
        if (Array.isArray(games) && games.length > 0) {
          games.forEach(game => {
            if (game.away) teamsPlayingToday.add(game.away);
            if (game.home) teamsPlayingToday.add(game.home);
          });
          console.log(`   Teams playing today (from Tank01): ${Array.from(teamsPlayingToday).join(', ')}`);
        } else {
          console.warn('⚠️ No games fetched – no players will match today\'s slate');
        }

        // ----- Get enriched players (already includes ADP) -----
        const enrichedPlayers = await getEnrichedPlayers(sport);
        console.log(`   Enriched players count: ${enrichedPlayers.length}`);
        if (enrichedPlayers.length === 0) {
          console.error('❌ No players loaded!');
        } else {
          console.log('   First 3 players (name, team):',
            enrichedPlayers.slice(0,3).map(p => `${p.name} (${p.team})`).join(', '));
        }

        // ----- Filter to only players from tonight's games -----
        const playersInSlate = enrichedPlayers.filter(p => {
          return p.team && teamsPlayingToday.has(p.team);
        });
        console.log(`   Players in tonight's slate: ${playersInSlate.length} of ${enrichedPlayers.length}`);

        // ----- Merge ADP (already present) into slate players -----
        const mergedPlayers = playersInSlate.map(p => {
          const salary = p.salary || 5000;
          const projection = p.projection || 0;
          return {
            playerId: p.playerId,
            name: p.name,
            team: p.team,
            position: p.position || 'N/A',
            salary,
            projection,
            valueScore: salary > 0 ? (projection / salary) * 1000 : 0,
            adp: p.adp || 999,   // use ADP from enriched player
            injury_status: p.injury_status || 'Healthy',
            ceiling: projection * 1.2,
            floor: projection * 0.8,
            keyFactors: ['Projected volume', 'Matchup', 'Injury status']
          };
        });

        console.log(`   Merged players count: ${mergedPlayers.length}`);

        // ----- Sort by valueScore -----
        let sorted = [...mergedPlayers].sort((a, b) => (b.valueScore || 0) - (a.valueScore || 0));
        console.log(`   Sorted players, top 3:`, sorted.slice(0,3).map(p => p.name));

        // ----- Simulate previous picks if a pick number is provided -----
        if (pick) {
          const pickNum = parseInt(pick, 10);
          if (!isNaN(pickNum) && pickNum > 1) {
            const takenIds = new Set();
            for (let i = 0; i < pickNum - 1; i++) {
              const nextPick = sorted.find(p => !takenIds.has(p.playerId));
              if (nextPick) {
                takenIds.add(nextPick.playerId);
              } else {
                break;
              }
            }
            sorted = sorted.filter(p => !takenIds.has(p.playerId));
            console.log(`   After simulating ${pickNum - 1} picks, ${sorted.length} players left`);
          }
        }

        // ----- Apply position filter if requested -----
        if (position) {
          sorted = sorted.filter(p => p.position === position);
          console.log(`   After position filter (${position}): ${sorted.length} players left`);
        }

        // ----- Format the final ranked list -----
        const ranked = sorted.slice(0, parseInt(limit)).map((p, idx) => ({
          playerId: p.playerId,
          name: p.name,
          team: p.team,
          position: p.position,
          salary: p.salary,
          projectedPoints: p.projection,
          valueScore: p.valueScore,
          adp: p.adp,
          expertRank: idx + 1,
          tier: Math.floor(idx / 12) + 1,
          injuryRisk: p.injury_status,
          keyFactors: p.keyFactors
        }));

        console.log(`   Returning ${ranked.length} players (from tonight's slate)`);
        if (ranked.length > 0) {
          console.log('   First ranked player:', ranked[0]);
        }

        return {
          success: true,
          data: ranked,
          count: ranked.length,
          source: teamsPlayingToday.size > 0 ? 'enriched-with-slate-filter' : 'enriched-no-slate'
        };
      },
      300
    );

    res.json(response);

  } catch (error) {
    console.error('❌ Error in /api/draft/rankings:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/draft/save', async (req, res) => {
  try {
    const draftData = req.body;
    if (!draftData.userId) {
      return res.status(400).json({ success: false, error: 'userId is required' });
    }
    const draft = new DraftRecommendation(draftData);
    await draft.save();
    
    if (redisCacheClient) {
      try {
        await redisCacheClient.del('draft:strategies:popular');
        // Simple pattern deletion would require SCAN, skipping for now
        // await redisCacheClient.delPattern('draft:history:*');
      } catch (error) {
        console.warn('⚠️ Failed to invalidate caches:', error.message);
      }
    }
    
    res.json({ success: true, draftId: draft._id });
  } catch (error) {
    console.error('Error saving draft:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/draft/history', async (req, res) => {
  try {
    const { userId, sport, status } = req.query;
    const query = {};
    if (userId) query.userId = userId;
    if (sport) query.sport = sport.toUpperCase();
    if (status) query.status = status;

    const cacheKey = `draft:history:${userId || 'all'}:${sport || 'all'}:${status || 'all'}`;
    
    const drafts = await getCachedOrFetch(
      cacheKey,
      async () => {
        return await DraftRecommendation.find(query)
          .sort({ createdAt: -1 })
          .limit(50)
          .lean();
      },
      300
    );
    
    res.json({ success: true, data: drafts, count: drafts.length });
  } catch (error) {
    console.error('Error fetching draft history:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/draft/strategies/popular', async (req, res) => {
  try {
    const { sport } = req.query;
    const cacheKey = `draft:strategies:popular:${sport || 'all'}`;
    
    const strategies = await getCachedOrFetch(
      cacheKey,
      async () => {
        const match = sport ? { sport: sport.toUpperCase(), status: 'completed' } : { status: 'completed' };
        return await DraftRecommendation.aggregate([
          { $match: match },
          { $group: { _id: '$type', count: { $sum: 1 }, avgTotalValue: { $avg: '$totalValue' } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ]);
      },
      3600
    );
    
    res.json({ success: true, data: strategies });
  } catch (error) {
    console.error('Error fetching popular strategies:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ====================
// SYSTEM STATUS
// ====================
app.get('/api/system/status', (req, res) => {
  const status = {
    timestamp: new Date().toISOString(),
    version: 'v3.9',
    caching: {
      redis: redisCacheClient ? '✅ Connected' : '⚠️ Disabled',
      nodeCache: '✅ Active (fallback)',
      cacheKeys: cache.keys().length,
      tank01Cache: '✅ Using Redis caching with TTLs (5min-1hr)'
    },
    endpoints: {
      prizepicks: { path: '/api/prizepicks/selections', status: '✅ Healthy', source: 'the_odds_api+static+opponent' },
      fantasyhub: { path: '/api/fantasyhub/players', status: '✅ Healthy', source: 'nba_api_service+static+opponent' },
      odds_api: { path: '/api/theoddsapi/playerprops', status: '✅ Healthy', source: 'the_odds_api+static' }
    },
    data_sources: {
      the_odds_api: { status: process.env.ODDS_API_KEY ? '✅ Active' : '⚠️ Missing key', key: process.env.ODDS_API_KEY ? 'present' : 'missing' },
      nba_api_service: { status: '✅ Active (NBA Data API)', note: 'Free, no key required' },
      rapidapi: { status: process.env.RAPIDAPI_KEY ? '✅ Available' : '⚠️ Missing', key: process.env.RAPIDAPI_KEY ? 'present' : 'missing' },
      static_2026_python: { status: staticNBAPlayers.length ? `✅ Loaded (${staticNBAPlayers.length} players)` : '⚠️ Not loaded' }
    }
  };
  res.json(status);
});

// ====================
// CURATED STATIC FALLBACK
// ====================
function generateIntelligentFantasyFallback(sport = 'nba') {
  console.log('   🛠️ Using curated static fallback (2025-26 per‑game averages)');
  return [
    { id: 'jokic', name: 'Nikola Jokic', team: 'DEN', position: 'C', points: 26.5, rebounds: 12.3, assists: 9.2, fantasy_points: 55.2, salary: 11400, injury_status: 'Healthy' },
    { id: 'doncic', name: 'Luka Doncic', team: 'LAL', position: 'G', points: 28.8, rebounds: 8.6, assists: 8.4, fantasy_points: 52.1, salary: 11200, injury_status: 'Healthy' },
    { id: 'sga', name: 'Shai Gilgeous-Alexander', team: 'OKC', position: 'G', points: 31.2, rebounds: 5.5, assists: 6.4, fantasy_points: 49.3, salary: 10800, injury_status: 'Healthy' },
    { id: 'giannis', name: 'Giannis Antetokounmpo', team: 'MIL', position: 'F', points: 31.0, rebounds: 11.8, assists: 6.2, fantasy_points: 54.8, salary: 11500, injury_status: 'Healthy' },
    { id: 'tatum', name: 'Jayson Tatum', team: 'BOS', position: 'F', points: 27.5, rebounds: 8.5, assists: 5.0, fantasy_points: 46.0, salary: 10500, injury_status: 'Healthy' },
    { id: 'jalen-johnson', name: 'Jalen Johnson', team: 'ATL', position: 'F', points: 19.8, rebounds: 9.5, assists: 4.2, fantasy_points: 36.5, salary: 8500, injury_status: 'Healthy' },
    { id: 'cunningham', name: 'Cade Cunningham', team: 'DET', position: 'G', points: 23.5, rebounds: 5.5, assists: 7.5, fantasy_points: 42.0, salary: 9500, injury_status: 'Healthy' },
    { id: 'maxey', name: 'Tyrese Maxey', team: 'PHI', position: 'G', points: 25.0, rebounds: 3.8, assists: 6.2, fantasy_points: 40.5, salary: 9200, injury_status: 'Healthy' },
    { id: 'wembanyama', name: 'Victor Wembanyama', team: 'SAS', position: 'C', points: 22.0, rebounds: 10.5, assists: 3.5, fantasy_points: 43.0, salary: 9800, injury_status: 'Healthy' },
    { id: 'curry', name: 'Stephen Curry', team: 'GSW', position: 'G', points: 26.0, rebounds: 4.5, assists: 5.0, fantasy_points: 41.0, salary: 9300, injury_status: 'Healthy' },
    { id: 'lebron', name: 'LeBron James', team: 'LAL', position: 'F', points: 25.5, rebounds: 7.5, assists: 7.5, fantasy_points: 44.0, salary: 10000, injury_status: 'Healthy' },
    { id: 'brown', name: 'Jaylen Brown', team: 'BOS', position: 'F', points: 23.5, rebounds: 5.5, assists: 3.5, fantasy_points: 37.5, salary: 8800, injury_status: 'Healthy' },
    { id: 'brunson', name: 'Jalen Brunson', team: 'NYK', position: 'G', points: 24.5, rebounds: 3.5, assists: 6.5, fantasy_points: 40.0, salary: 9000, injury_status: 'Healthy' },
    { id: 'giddey', name: 'Josh Giddey', team: 'CHI', position: 'G', points: 14.5, rebounds: 7.5, assists: 6.0, fantasy_points: 32.5, salary: 7800, injury_status: 'Healthy' },
    { id: 'towns', name: 'Karl-Anthony Towns', team: 'NYK', position: 'C', points: 22.5, rebounds: 10.5, assists: 3.0, fantasy_points: 41.0, salary: 9400, injury_status: 'Healthy' },
    { id: 'reaves', name: 'Austin Reaves', team: 'LAL', position: 'G', points: 16.5, rebounds: 4.5, assists: 5.5, fantasy_points: 29.5, salary: 7500, injury_status: 'Healthy' },
    { id: 'hield', name: 'Buddy Hield', team: 'ATL', position: 'G', points: 12.5, rebounds: 3.2, assists: 2.8, fantasy_points: 21.0, salary: 6000, injury_status: 'Healthy' },
    { id: 'houstan', name: 'Caleb Houstan', team: 'ATL', position: 'F', points: 6.5, rebounds: 2.5, assists: 0.8, fantasy_points: 10.5, salary: 3500, injury_status: 'Healthy' }
  ];
}

// ====================
// CATCH-ALL FOR /api/*
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
    api_sources: {
      nba_api_service: 'active',
      the_odds_api: process.env.ODDS_API_KEY ? 'key present' : 'key missing',
      rapidapi_key: process.env.RAPIDAPI_KEY ? 'present' : 'missing',
      static_2026_python: staticNBAPlayers.length
    },
    availableEndpoints: [
      '/api/nba', '/api/nba/games', '/api/nfl/games', '/api/nfl/stats', '/api/nfl/standings',
      '/api/nhl/games', '/api/nhl/players', '/api/nhl/standings', '/api/games', '/api/news',
      '/api/players', '/api/fantasy/teams', '/api/picks/daily', '/api/parlay/suggestions',
      '/api/kalshi/predictions', '/api/prizepicks/selections', '/api/prizepicks/analytics',
      '/api/match/analytics', '/api/advanced/analytics', '/api/player/stats/trends',
      '/api/secret/phrases', '/api/subscription/plans', '/api/sportsbooks', '/api/auth/health',
      '/api/admin/health', '/api/system/status', '/api/cors-test', '/api/frontend-test',
      '/api/theoddsapi/playerprops', '/api/fantasyhub/players', '/api/health/cache'
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
        '/api/nba', '/api/nba/games', '/api/nfl/games', '/api/nfl/stats', '/api/nfl/standings',
        '/api/nhl/games', '/api/nhl/players', '/api/nhl/standings', '/api/games', '/api/news',
        '/api/players', '/api/fantasy/teams', '/api/picks/daily', '/api/parlay/suggestions',
        '/api/kalshi/predictions', '/api/prizepicks/selections', '/api/prizepicks/analytics',
        '/api/match/analytics', '/api/advanced/analytics', '/api/player/stats/trends',
        '/api/secret/phrases', '/api/subscription/plans', '/api/sportsbooks', '/api/auth/health',
        '/api/admin/health', '/api/system/status', '/api/cors-test', '/api/frontend-test',
        '/api/theoddsapi/playerprops', '/api/fantasyhub/players', '/api/health/cache'
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
      available: ['/', '/health', '/api', '/api-docs', '/api/health/cache'],
      note: 'Visit /api for API endpoints or /api-docs for documentation'
    });
  }
});

// ====================
// ERROR HANDLER
// ====================
const errorHandler = (err, req, res, next) => {
  console.error('🔥 ERROR:', { message: err.message, stack: err.stack, path: req.path, method: req.method, timestamp: new Date().toISOString() });
  if (err.name === 'ValidationError') return res.status(400).json({ success: false, message: 'Validation Error', errors: err.errors });
  if (err.name === 'UnauthorizedError') return res.status(401).json({ success: false, message: 'Unauthorized' });
  if (err.message.includes('CORS')) {
    return res.status(403).json({ success: false, error: 'CORS Error', message: err.message, allowedOrigins: allowedOrigins.map(o => typeof o === 'string' ? o : o.source) });
  }
  res.status(err.status || 500).json({ success: false, message: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message });
};
app.use(errorHandler);

// ====================
// START SERVER
// ====================
async function startServer() {
  try {
    staticNBAPlayers = await fetchStaticNBAPlayers();
    staticNHLPlayers = await fetchStaticNHLPlayers();
    staticMLBPlayers = await fetchStaticMLBPlayers();   // <-- add this line
    staticNFLPlayers = []; // keep empty if not needed

    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/fantasydb';
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
    });
    console.log('✅ MongoDB connected');

    const server = app.listen(PORT, HOST, () => {
      console.log(`\n🎉 Server running on ${HOST}:${PORT}`);
      console.log(`🌐 CORS Enabled for: ${allowedOrigins.length} origins`);
      console.log(`🏥 Health: https://prizepicks-production.up.railway.app/health`);
      console.log(`📚 Docs: https://prizepicks-production.up.railway.app/api-docs`);
      console.log(`🔧 API: https://prizepicks-production.up.railway.app/api`);
      console.log(`📊 CACHE: Redis ${redisCacheClient ? '✅ Connected' : '❌ Disabled'} | NodeCache ✅ Active`);
      console.log(`📊 TANK01 CACHE: Using Redis with TTLs (5min-1hr)`);
      console.log(`\n📊 DATA SOURCES:`);
      console.log(`   ✅ NBA API Service (NBA Data API) – no key required`);
      console.log(`   ✅ The Odds API – key present: ${!!(process.env.ODDS_API_KEY || process.env.THE_ODDS_API_KEY)}`);
      console.log(`   ✅ RapidAPI – key present: ${!!process.env.RAPIDAPI_KEY}`);
      console.log(`   ✅ 2026 Static NBA Players – loaded: ${staticNBAPlayers.length}`);
      console.log(`   ✅ Static NHL Players – loaded: ${staticNHLPlayers.length}`);
      console.log(`\n🎯 KEY ENDPOINTS:`);
      console.log(`   GET /api/prizepicks/selections - PrizePicks selections (The Odds API + static + opponent adjustments)`);
      console.log(`   GET /api/fantasyhub/players   - Fantasy Hub with NBA API stats + static + opponent adjustments)`);
      console.log(`   GET /api/theoddsapi/playerprops - Raw The Odds API player props (enriched with static)`);
      console.log(`   GET /api/tank01/*             - All Tank01 endpoints (cached with Redis)`);
      console.log(`   GET /api/draft/rankings       - Draft rankings (with Tank01 Redis cache)`);
      console.log(`   GET /api/health/cache         - Cache health and statistics`);
      console.log(`\n✅ Server ready!`);
    });

    const shutdown = () => {
      console.log('\n🛑 Shutting down gracefully...');
      if (redisClient) redisClient.quit();
      if (redisCacheClient) redisCacheClient.quit();
      if (mongoose.connection.readyState === 1) mongoose.connection.close(false);
      server.close(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}

export { app };
