// services/tank01Service.js
import axios from 'axios';

const RAPIDAPI_HOST = 'tank01-fantasy-stats.p.rapidapi.com';
const API_KEY = process.env.RAPIDAPI_KEY;

// Generic caller with error handling
const callTank01 = async (endpoint, params = {}) => {
  try {
    const response = await axios.get(`https://${RAPIDAPI_HOST}${endpoint}`, {
      headers: {
        'x-rapidapi-host': RAPIDAPI_HOST,
        'x-rapidapi-key': API_KEY
      },
      params,
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    console.error(`Tank01 error (${endpoint}):`, error.response?.data || error.message);
    throw error;
  }
};

// ADP
export const getADP = async () => {
  const data = await callTank01('/getNBAADP');
  return data.body?.adpList || [];
};

// Projections (with default scoring)
export const getProjections = async (days = 7) => {
  const data = await callTank01('/getNBAProjections', {
    numOfDays: days,
    pts: 1,
    reb: 1.25,
    ast: 1.5,
    stl: 3,
    blk: 3,
    TOV: -1,
    mins: 0
  });
  return data.body?.playerProjections || {};
};

// Injuries
export const getInjuries = async () => {
  const data = await callTank01('/getNBAInjuryList');
  return data.body || [];
};

// News
export const getNews = async (maxItems = 10) => {
  const data = await callTank01('/getNBANews', { recentNews: true, maxItems });
  return data.body || [];
};

// Depth Charts
export const getDepthCharts = async () => {
  const data = await callTank01('/getNBADepthCharts');
  return data.body || [];
};

// Games for a specific date
export const getGamesForDate = async (date) => {
  const data = await callTank01('/getNBAGamesForDate', { gameDate: date });
  return data.body || [];
};

// Player info by name
export const getPlayerInfo = async (playerName) => {
  const data = await callTank01('/getNBAPlayerInfo', {
    playerName,
    statsToGet: 'averages'
  });
  return data.body || [];
};

// Team roster
export const getTeamRoster = async (teamAbv) => {
  const data = await callTank01('/getNBATeamRoster', {
    teamAbv,
    statsToGet: 'averages'
  });
  return data.body || [];
};

// Current info (season, date)
export const getCurrentInfo = async () => {
  const data = await callTank01('/getNBACurrentInfo');
  return data.body || {};
};

// Box score
export const getBoxScore = async (gameID, fantasyPoints = true) => {
  const params = { gameID };
  if (fantasyPoints) {
    params.fantasyPoints = true;
    params.pts = 1;
    params.reb = 1.25;
    params.ast = 1.5;
    params.stl = 3;
    params.blk = 3;
    params.TOV = -1;
    params.mins = 0;
  }
  const data = await callTank01('/getNBABoxScore', params);
  return data.body || {};
};

// ============= NEW FUNCTION: getPlayerList =============
// Fetches all players (combines team rosters or uses a direct endpoint)
export const getPlayerList = async (sport = 'nba') => {
  console.log(`📋 Fetching player list for ${sport} from Tank01...`);
  
  try {
    // For NBA, try to get all players. There are a few approaches:
    
    // Approach 1: If there's a direct endpoint for all players
    // const data = await callTank01('/getNBAPlayers');
    // return data.body || [];
    
    // Approach 2: Combine all team rosters (slower but works)
    const teams = ['ATL', 'BOS', 'BKN', 'CHA', 'CHI', 'CLE', 'DAL', 'DEN', 'DET', 'GSW',
                   'HOU', 'IND', 'LAC', 'LAL', 'MEM', 'MIA', 'MIL', 'MIN', 'NOP', 'NYK',
                   'OKC', 'ORL', 'PHI', 'PHX', 'POR', 'SAC', 'SAS', 'TOR', 'UTA', 'WAS'];
    
    let allPlayers = [];
    for (const team of teams) {
      try {
        const roster = await getTeamRoster(team);
        if (Array.isArray(roster)) {
          allPlayers = allPlayers.concat(roster);
        } else if (roster && typeof roster === 'object') {
          // Handle if roster is an object with players property
          const players = roster.players || roster.roster || [];
          allPlayers = allPlayers.concat(players);
        }
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (e) {
        console.warn(`⚠️ Failed to fetch roster for ${team}:`, e.message);
      }
    }
    
    // Deduplicate by playerId
    const uniquePlayers = Array.from(
      new Map(allPlayers.map(p => [p.playerId || p.playerID, p])).values()
    );
    
    console.log(`✅ Loaded ${uniquePlayers.length} unique players from Tank01`);
    return uniquePlayers;
    
  } catch (error) {
    console.error('❌ Error in getPlayerList:', error.message);
    return []; // Return empty array on failure
  }
};

// ============= DEFAULT EXPORT =============
// This allows both named imports and default imports to work
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
  getPlayerList,  // Added the new function
  // Aliases for backward compatibility
  getPlayerListV2: getPlayerList
};
