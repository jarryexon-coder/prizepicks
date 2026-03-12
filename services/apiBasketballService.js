import axios from 'axios';

const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY;
const BASE_URL = 'https://api-basketball.p.rapidapi.com';

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'X-RapidAPI-Key': RAPIDAPI_KEY,
    'X-RapidAPI-Host': 'api-basketball.p.rapidapi.com'
  }
});

/**
 * Get all NBA players with their season averages
 */
export async function getPlayersWithAverages(season = '2025') {
  try {
    // First, get all teams to fetch rosters
    const teamsResponse = await apiClient.get('/teams', {
      params: { league: '12', season } // league 12 = NBA
    });
    
    const teams = teamsResponse.data.response;
    const allPlayers = [];
    
    // Fetch roster for each team
    for (const team of teams) {
      const rosterResponse = await apiClient.get('/players', {
        params: {
          team: team.id,
          season
        }
      });
      
      const players = rosterResponse.data.response;
      
      // For each player, get their statistics
      for (const player of players) {
        const statsResponse = await apiClient.get('/players/statistics', {
          params: {
            id: player.id,
            season
          }
        });
        
        const stats = statsResponse.data.response[0];
        
        allPlayers.push({
          id: player.id,
          name: player.name,
          team: team.name,
          position: player.position,
          points: stats?.points || 0,
          rebounds: stats?.rebounds?.total || 0,
          assists: stats?.assists || 0,
          fantasy_points: (stats?.points || 0) + 
                         (stats?.rebounds?.total || 0) * 1.2 + 
                         (stats?.assists || 0) * 1.5,
          games_played: stats?.games || 1
        });
      }
      
      // Add delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    return allPlayers;
  } catch (error) {
    console.error('Error fetching NBA data:', error);
    throw error;
  }
}

/**
 * Get player game log for a specific player
 */
export async function getPlayerGameLog(playerId, season = '2025') {
  try {
    const response = await apiClient.get('/players/gamelog', {
      params: {
        id: playerId,
        season
      }
    });
    return response.data.response;
  } catch (error) {
    console.error('Error fetching player game log:', error);
    throw error;
  }
}
