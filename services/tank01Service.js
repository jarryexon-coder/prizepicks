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

    const response = await axios.get(`https://${host}${endpoint}`, {
      headers: {
        'X-RapidAPI-Key': API_KEY,
        'X-RapidAPI-Host': host,
      },
      params,
      timeout: 10000,
    });
    return response.data;
  } catch (error) {
    console.error(`Tank01 error (${sport} ${endpoint}):`, error.response?.data || error.message);
    throw error;
  }
};

// ============= NBA‑specific functions (default sport = 'nba') =============

export const getADP = async (sport = 'nba') => {
  const data = await callTank01('/getNBAADP', {}, sport);
  return data.body?.adpList || [];
};

export const getProjections = async (days = 7, sport = 'nba') => {
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
  return data.body?.playerProjections || {};
};

export const getInjuries = async (sport = 'nba') => {
  const data = await callTank01('/getNBAInjuryList', {}, sport);
  return data.body || [];
};

export const getNews = async (maxItems = 10, sport = 'nba') => {
  const data = await callTank01('/getNBANews', { recentNews: true, maxItems }, sport);
  return data.body || [];
};

export const getDepthCharts = async (sport = 'nba') => {
  const data = await callTank01('/getNBADepthCharts', {}, sport);
  return data.body || [];
};

export const getGamesForDate = async (date, sport = 'nba') => {
  const data = await callTank01('/getNBAGamesForDate', { gameDate: date }, sport);
  return data.body || [];
};

export const getPlayerInfo = async (playerName, sport = 'nba') => {
  const data = await callTank01('/getNBAPlayerInfo', {
    playerName,
    statsToGet: 'averages',
  }, sport);
  return data.body || [];
};

export const getTeamRoster = async (teamAbv, sport = 'nba', getStats = 'true', fantasyPoints = 'true') => {
  // For NHL and MLB, the endpoint and parameter names may differ slightly.
  // We'll construct the endpoint based on sport.
  let endpoint;
  if (sport === 'nba') endpoint = '/getNBATeamRoster';
  else if (sport === 'nhl') endpoint = '/getNHLTeamRoster';
  else if (sport === 'mlb') endpoint = '/getMLBTeamRoster';
  else throw new Error(`Unsupported sport for roster: ${sport}`);

  const params = {
    teamAbv,          // Tank01 usually uses teamAbv for all sports
    getStats,
    fantasyPoints,
  };

  const data = await callTank01(endpoint, params, sport);
  return data.body || {};
};

export const getCurrentInfo = async (sport = 'nba') => {
  const data = await callTank01('/getNBACurrentInfo', {}, sport);
  return data.body || {};
};

export const getBoxScore = async (gameID, fantasyPoints = true, sport = 'nba') => {
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
  const data = await callTank01('/getNBABoxScore', params, sport);
  return data.body || {};
};

// ============= MLB & NHL team list functions (already correct) =============

export async function getMLBTeams() {
  const url = 'https://tank01-mlb-live-in-game-real-time-statistics.p.rapidapi.com/getMLBTeams';
  const response = await axios.get(url, {
    headers: {
      'X-RapidAPI-Key': process.env.RAPIDAPI_KEY,
      'X-RapidAPI-Host': 'tank01-mlb-live-in-game-real-time-statistics.p.rapidapi.com',
    },
  });
  return response.data?.body || response.data;
}

export async function getNHLTeams() {
  const url = 'https://tank01-nhl-live-in-game-real-time-statistics-nhl.p.rapidapi.com/getNHLTeams';
  const response = await axios.get(url, {
    headers: {
      'X-RapidAPI-Key': process.env.RAPIDAPI_KEY,
      'X-RapidAPI-Host': 'tank01-nhl-live-in-game-real-time-statistics-nhl.p.rapidapi.com',
    },
  });
  return response.data?.body || response.data;
}

// ============= getPlayerList (NBA only, can be extended later) =============

export const getPlayerList = async (sport = 'nba') => {
  console.log(`📋 Fetching player list for ${sport} from Tank01...`);

  try {
    // For now, only NBA is supported. You can extend this later for MLB/NHL.
    if (sport !== 'nba') {
      console.warn(`getPlayerList for ${sport} not implemented yet, returning empty array.`);
      return [];
    }

    // Combine all team rosters (NBA only)
    const teams = ['ATL', 'BOS', 'BKN', 'CHA', 'CHI', 'CLE', 'DAL', 'DEN', 'DET', 'GSW',
      'HOU', 'IND', 'LAC', 'LAL', 'MEM', 'MIA', 'MIL', 'MIN', 'NOP', 'NYK',
      'OKC', 'ORL', 'PHI', 'PHX', 'POR', 'SAC', 'SAS', 'TOR', 'UTA', 'WAS'];

    let allPlayers = [];
    for (const team of teams) {
      try {
        const roster = await getTeamRoster(team, 'nba');
        if (Array.isArray(roster)) {
          allPlayers = allPlayers.concat(roster);
        } else if (roster && typeof roster === 'object') {
          const players = roster.players || roster.roster || [];
          allPlayers = allPlayers.concat(players);
        }
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
