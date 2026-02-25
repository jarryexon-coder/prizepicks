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
