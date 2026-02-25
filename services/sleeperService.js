import axios from 'axios';

const BASE_URL = 'https://api.sleeper.app/v1';

export const getUserLeagues = async (username, sport = 'nba', season = '2025') => {
  try {
    // Get user ID
    const userRes = await axios.get(`${BASE_URL}/user/${username}`);
    const userId = userRes.data.user_id;
    
    // Get leagues for specified season
    const leaguesRes = await axios.get(`${BASE_URL}/user/${userId}/leagues/${sport}/${season}`);
    return leaguesRes.data;
  } catch (error) {
    console.error('Sleeper API error:', error.message);
    return [];
  }
};

export const getLeagueRosters = async (leagueId) => {
  try {
    const res = await axios.get(`${BASE_URL}/league/${leagueId}/rosters`);
    return res.data;
  } catch (error) {
    console.error('Error fetching rosters:', error.message);
    return [];
  }
};

export const getAllPlayers = async (sport = 'nba') => {
  try {
    const res = await axios.get(`${BASE_URL}/players/${sport}`);
    return res.data;
  } catch (error) {
    console.error('Error fetching players:', error.message);
    return {};
  }
};
