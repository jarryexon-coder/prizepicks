// services/tank01Service.js
import axios from 'axios';

// RapidAPI hosts for each sport
const HOSTS = {
  nba: 'tank01-fantasy-stats.p.rapidapi.com',
  nhl: 'tank01-nhl-live-in-game-real-time-statistics-nhl.p.rapidapi.com',
  mlb: 'tank01-mlb-live-in-game-real-time-statistics.p.rapidapi.com',
};

const API_KEY = process.env.RAPIDAPI_KEY;

// Generic caller with error handling and sport‑specific host
const callTank01 = async (endpoint, params = {}, sport = 'nba') => {
  try {
    const host = HOSTS[sport];
    if (!host) throw new Error(`Unsupported sport: ${sport}`);

    const url = `https://${host}${endpoint}`;
    console.log(`📡 Tank01 request: ${url}`, { params, sport });

    const response = await axios.get(url, {
      headers: {
        'X-RapidAPI-Key': API_KEY,
        'X-RapidAPI-Host': host,
      },
      params,
      timeout: 10000,
    });

    // Most Tank01 endpoints return { statusCode, body, ... }
    // We'll return the body if it exists, otherwise the whole response
    return response.data?.body ?? response.data;
  } catch (error) {
    console.error(`❌ Tank01 error (${sport} ${endpoint}):`, error.response?.data || error.message);
    throw error;
  }
};

// ==================== Sport‑specific endpoint maps ====================
const ENDPOINTS = {
  gamesForDate: {
    nba: '/getNBAGamesForDate',
    nhl: '/getNHLGamesForDate',
    mlb: '/getMLBGamesForDate',
    nfl: '/getNFLGamesForDate', // placeholder if needed
  },
  teamRoster: {
    nba: '/getNBATeamRoster',
    nhl: '/getNHLTeamRoster',
    mlb: '/getMLBTeamRoster',
  },
  playerInfo: {
    nba: '/getNBAPlayerInfo',
    nhl: '/getNHLPlayerInfo',
    mlb: '/getMLBPlayerInfo',
  },
  boxScore: {
    nba: '/getNBABoxScore',
    nhl: '/getNHLBoxScore',
    mlb: '/getMLBBoxScore',
  },
  currentInfo: {
    nba: '/getNBACurrentInfo',
    nhl: '/getNHLCurrentInfo',
    mlb: '/getMLBCurrentInfo',
  },
  // Projections, injuries, ADP, news, depth charts are currently NBA‑only.
  // We'll keep them as NBA functions; if called for other sports, we throw.
};

// ============= NBA‑only functions (will throw if sport !== 'nba') =============

const ensureNBA = (sport, fnName) => {
  if (sport !== 'nba') {
    throw new Error(`${fnName} is only available for NBA (requested: ${sport})`);
  }
};

export const getADP = async (sport = 'nba') => {
  ensureNBA(sport, 'getADP');
  const data = await callTank01('/getNBAADP', {}, sport);
  return data.adpList || [];
};

export const getProjections = async (days = 7, sport = 'nba') => {
  ensureNBA(sport, 'getProjections');
  const data = await callTank01('/getNBAProjections', {
    numOfDays: days,
    pts: 1,
    reb: 1.25,
    ast: 1.5,
    stl: 3,
    blk: 3,
    TOV: -1,
    mins: 0,
  }, sport);
  return data.playerProjections || {};
};

export const getInjuries = async (sport = 'nba') => {
  ensureNBA(sport, 'getInjuries');
  const data = await callTank01('/getNBAInjuryList', {}, sport);
  return data || [];
};

export const getNews = async (maxItems = 10, sport = 'nba') => {
  ensureNBA(sport, 'getNews');
  const data = await callTank01('/getNBANews', { recentNews: true, maxItems }, sport);
  return data || [];
};

export const getDepthCharts = async (sport = 'nba') => {
  ensureNBA(sport, 'getDepthCharts');
  const data = await callTank01('/getNBADepthCharts', {}, sport);
  return data || [];
};

// ============= Sport‑agnostic functions (use endpoint map) =============

export const getGamesForDate = async (date, sport = 'nba') => {
  const endpoint = ENDPOINTS.gamesForDate[sport];
  if (!endpoint) throw new Error(`No games endpoint for sport: ${sport}`);
  const data = await callTank01(endpoint, { gameDate: date }, sport);
  // Tank01 returns an array of games; ensure it's an array
  return Array.isArray(data) ? data : (data.games || []);
};

export const getPlayerInfo = async (playerName, sport = 'nba') => {
  const endpoint = ENDPOINTS.playerInfo[sport];
  if (!endpoint) throw new Error(`No player info endpoint for sport: ${sport}`);
  const params = sport === 'nba'
    ? { playerName, statsToGet: 'averages' }
    : { playerName, getStats: 'true' }; // NHL/MLB use getStats parameter
  const data = await callTank01(endpoint, params, sport);
  // Tank01 returns an array of matching players
  return Array.isArray(data) ? data : [];
};

export const getTeamRoster = async (teamAbv, sport = 'nba', getStats = 'true', fantasyPoints = 'true') => {
  const endpoint = ENDPOINTS.teamRoster[sport];
  if (!endpoint) throw new Error(`No roster endpoint for sport: ${sport}`);

  const params = {
    teamAbv, // Tank01 uses teamAbv for all sports
    getStats,
    fantasyPoints,
  };

  const data = await callTank01(endpoint, params, sport);
  // The roster may be returned directly as an array, or inside a `roster` field
  if (Array.isArray(data)) return data;
  if (data?.roster && Array.isArray(data.roster)) return data.roster;
  return [];
};

export const getCurrentInfo = async (sport = 'nba') => {
  const endpoint = ENDPOINTS.currentInfo[sport];
  if (!endpoint) throw new Error(`No current info endpoint for sport: ${sport}`);
  const data = await callTank01(endpoint, {}, sport);
  return data || {};
};

export const getBoxScore = async (gameID, fantasyPoints = true, sport = 'nba') => {
  const endpoint = ENDPOINTS.boxScore[sport];
  if (!endpoint) throw new Error(`No box score endpoint for sport: ${sport}`);

  const params = { gameID };
  if (fantasyPoints) {
    // For NBA, you can pass scoring weights; for others, just request fantasyPoints
    if (sport === 'nba') {
      params.fantasyPoints = true;
      params.pts = 1;
      params.reb = 1.25;
      params.ast = 1.5;
      params.stl = 3;
      params.blk = 3;
      params.TOV = -1;
      params.mins = 0;
    } else {
      params.fantasyPoints = true;
    }
  }
  const data = await callTank01(endpoint, params, sport);
  return data || {};
};

// ============= MLB & NHL team list functions (unchanged, they work) =============

export async function getMLBTeams() {
  const url = 'https://tank01-mlb-live-in-game-real-time-statistics.p.rapidapi.com/getMLBTeams';
  const response = await axios.get(url, {
    headers: {
      'X-RapidAPI-Key': API_KEY,
      'X-RapidAPI-Host': HOSTS.mlb,
    },
  });
  return response.data?.body || response.data;
}

export async function getNHLTeams() {
  const url = 'https://tank01-nhl-live-in-game-real-time-statistics-nhl.p.rapidapi.com/getNHLTeams';
  const response = await axios.get(url, {
    headers: {
      'X-RapidAPI-Key': API_KEY,
      'X-RapidAPI-Host': HOSTS.nhl,
    },
  });
  return response.data?.body || response.data;
}

// ============= getPlayerList – now supports NHL and MLB =============
export const getPlayerList = async (sport = 'nba') => {
  console.log(`📋 Fetching player list for ${sport} from Tank01...`);

  try {
    // For NBA, use the existing method (combine rosters) because it's robust and includes stats
    if (sport === 'nba') {
      const teams = ['ATL', 'BOS', 'BKN', 'CHA', 'CHI', 'CLE', 'DAL', 'DEN', 'DET', 'GSW',
        'HOU', 'IND', 'LAC', 'LAL', 'MEM', 'MIA', 'MIL', 'MIN', 'NOP', 'NYK',
        'OKC', 'ORL', 'PHI', 'PHX', 'POR', 'SAC', 'SAS', 'TOR', 'UTA', 'WAS'];

      let allPlayers = [];
      for (const team of teams) {
        try {
          const roster = await getTeamRoster(team, 'nba');
          if (Array.isArray(roster)) {
            allPlayers = allPlayers.concat(roster);
          }
          await new Promise(resolve => setTimeout(resolve, 100)); // be gentle
        } catch (e) {
          console.warn(`⚠️ Failed to fetch roster for ${team}:`, e.message);
        }
      }

      // Deduplicate by playerId
      const uniquePlayers = Array.from(
        new Map(allPlayers.map(p => [p.playerId || p.playerID, p])).values()
      );

      console.log(`✅ Loaded ${uniquePlayers.length} unique NBA players from Tank01`);
      return uniquePlayers;
    }

    // For NHL and MLB, use the dedicated player list endpoint with stats
    const endpoint = sport === 'nhl' ? '/getNHLPlayerList' : '/getMLBPlayerList';
    const params = { getStats: 'true' }; // Request stats along with player info
    const data = await callTank01(endpoint, params, sport);

    // The response might be an array directly, or wrapped in a `body` or `players` field
    let players = [];
    if (Array.isArray(data)) {
      players = data;
    } else if (data?.body && Array.isArray(data.body)) {
      players = data.body;
    } else if (data?.players && Array.isArray(data.players)) {
      players = data.players;
    }

    console.log(`✅ Fetched ${players.length} players from Tank01 ${sport.toUpperCase()} player list`);
    return players;

  } catch (error) {
    console.error(`❌ Error in getPlayerList for ${sport}:`, error.message);
    // Fallback: return empty array – the master map will then use static Python data
    return [];
  }
};

// ============= Default export for backward compatibility =============
export default {
  getADP,
  getProjections,
  getInjuries,
  getNews,
  getDepthCharts,
  getGamesForDate,
  getPlayerInfo,
  getTeamRoster,
  getCurrentInfo,
  getBoxScore,
  getPlayerList,
  getMLBTeams,
  getNHLTeams,
};
