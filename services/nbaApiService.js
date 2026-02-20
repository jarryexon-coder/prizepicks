import axios from 'axios';
import NodeCache from 'node-cache';

// Cache for 5 minutes
const cache = new NodeCache({ stdTTL: 300 });

// Player name normalization utilities
function normalizePlayerName(name) {
  if (!name || typeof name !== 'string') return '';
  
  // Remove everything in parentheses and brackets
  let normalized = name.replace(/\s*\([^)]*\)/g, '');
  normalized = normalized.replace(/\s*\[[^\]]*\]/g, '');
  
  // Remove team abbreviations and special markers
  normalized = normalized.replace(/\s*[-–]\s*[A-Z]{2,4}$/g, '');
  normalized = normalized.replace(/\s*[A-Z]{2,4}$/g, '');
  
  // Handle special characters
  normalized = normalized
    .replace(/č/g, 'c').replace(/ć/g, 'c')
    .replace(/š/g, 's').replace(/ž/g, 'z')
    .toLowerCase()
    .trim();
  
  // Handle common variations
  const variations = {
    'tim hardaway jr': 'tim hardaway jr',
    'lebron james': 'lebron james',
    'karl-anthony towns': 'karl-anthony towns',
    'og anunoby': 'og anunoby',
    'jrue holiday': 'jrue holiday',
    'c.j. mccollum': 'cj mccollum',
    'jonas valanciunas': 'jonas valanciunas',
    'nikola jokic': 'nikola jokic',
    'luka doncic': 'luka doncic',
    'jalen brunson': 'jalen brunson'
  };
  
  return variations[normalized] || normalized;
}

class NBAApiService {
  constructor() {
    this.sportradarKey = process.env.SPORTRADAR_API_KEY;
    this.rapidapiKey = process.env.RAPIDAPI_KEY;
  }

  /**
   * Find player using NBA Data API
   */
  async findPlayerInNBAData(playerName) {
    const cacheKey = `player_search_${playerName}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    try {
      const normalizedName = normalizePlayerName(playerName);
      
      // Use NBA Data API (official source)
      const nbaPlayersUrl = 'http://data.nba.net/data/10s/prod/v1/2024/players.json';
      const response = await axios.get(nbaPlayersUrl);
      const players = response.data.league?.standard || [];
      
      // Multiple search strategies
      const foundPlayer = this.findPlayerWithStrategies(players, normalizedName);
      
      if (foundPlayer) {
        cache.set(cacheKey, foundPlayer.personId);
        return foundPlayer.personId;
      }
      
      // Strategy 2: Fallback to RapidAPI NBA stats if needed
      if (this.rapidapiKey) {
        const rapidapiId = await this.findPlayerInRapidAPI(playerName);
        if (rapidapiId) {
          cache.set(cacheKey, rapidapiId);
          return rapidapiId;
        }
      }
      
      return null;
      
    } catch (error) {
      console.error('NBA Data API player search error:', error.message);
      return null;
    }
  }

  findPlayerWithStrategies(players, normalizedName) {
    const strategies = [
      // Exact match: "lebron james"
      players.find(p => {
        const fullName = `${p.firstName?.toLowerCase()} ${p.lastName?.toLowerCase()}`;
        return fullName === normalizedName;
      }),
      
      // Handle Jr., III, etc: "tim hardaway jr" -> "tim hardaway"
      players.find(p => {
        const simpleName = normalizedName.replace(/\s(jr|sr|iii|ii|iv)$/i, '').trim();
        const playerName = `${p.firstName?.toLowerCase()} ${p.lastName?.toLowerCase()}`;
        return playerName === simpleName;
      }),
      
      // Last name match with first initial
      players.find(p => {
        const nameParts = normalizedName.split(' ');
        return p.lastName?.toLowerCase() === nameParts[nameParts.length - 1] &&
               p.firstName?.[0]?.toLowerCase() === normalizedName[0];
      }),
      
      // Contains match
      players.find(p => {
        const nameParts = normalizedName.split(' ');
        return nameParts.some(part => 
          p.firstName?.toLowerCase().includes(part) ||
          p.lastName?.toLowerCase().includes(part)
        );
      })
    ];
    
    return strategies.find(p => p);
  }

  /**
   * Get player stats using NBA Data API
   */
  async getPlayerStats(playerName) {
    const playerId = await this.findPlayerInNBAData(playerName);
    
    if (!playerId) {
      return { 
        playerName, 
        found: false,
        source: 'nba_data_api'
      };
    }

    try {
      // Get player profile from NBA Data API
      const profileUrl = `http://data.nba.net/data/10s/prod/v1/2024/players/${playerId}_profile.json`;
      const profileRes = await axios.get(profileUrl);
      
      // Get game log
      const statsUrl = `http://data.nba.net/data/10s/prod/v1/2024/players/${playerId}_gamelog.json`;
      const statsRes = await axios.get(statsUrl);
      
      const profile = profileRes.data.league?.standard?.stats?.latest;
      const games = statsRes.data.league?.standard?.games || [];
      
      if (!profile) {
        return { playerName, found: false, source: 'nba_data_api' };
      }
      
      // Calculate recent stats (last 5 games)
      const recentGames = games.slice(0, 5);
      const recentStats = {
        ppg: recentGames.length > 0 ? 
          recentGames.reduce((sum, game) => sum + (game.stats?.points || 0), 0) / recentGames.length : 0,
        rpg: recentGames.length > 0 ?
          recentGames.reduce((sum, game) => sum + (game.stats?.totReb || 0), 0) / recentGames.length : 0,
        apg: recentGames.length > 0 ?
          recentGames.reduce((sum, game) => sum + (game.stats?.assists || 0), 0) / recentGames.length : 0,
        gamesCount: recentGames.length
      };

      return {
        playerName: `${profile.firstName} ${profile.lastName}`,
        playerId,
        team: `${profile.teamCity} ${profile.teamName}`,
        position: profile.pos,
        recentStats,
        seasonStats: {
          gamesPlayed: profile.gamesPlayed,
          points: profile.ppg,
          rebounds: profile.rpg,
          assists: profile.apg,
          fgPct: profile.fgp
        },
        found: true,
        source: 'nba_data_api'
      };
      
    } catch (error) {
      console.error(`NBA Data API stats error for ${playerName}:`, error.message);
      
      // Fallback to Sportradar if available
      if (this.sportradarKey) {
        return await this.getSportradarFallback(playerName);
      }
      
      return { 
        playerName, 
        found: false, 
        error: error.message,
        source: 'nba_data_api'
      };
    }
  }

  /**
   * Fallback to Sportradar API if NBA Data API fails
   */
  async getSportradarFallback(playerName) {
    try {
      const searchUrl = `https://api.sportradar.com/nba/trial/v8/en/players/search.json?name=${encodeURIComponent(playerName)}&api_key=${this.sportradarKey}`;
      const searchRes = await axios.get(searchUrl);
      
      if (searchRes.data.players?.length > 0) {
        const player = searchRes.data.players[0];
        const profileUrl = `https://api.sportradar.com/nba/trial/v8/en/players/${player.id}/profile.json?api_key=${this.sportradarKey}`;
        const profileRes = await axios.get(profileUrl);
        
        return {
          playerName: player.full_name,
          playerId: player.id,
          team: player.team?.market + ' ' + player.team?.name,
          position: player.primary_position,
          found: true,
          source: 'sportradar_fallback'
        };
      }
    } catch (error) {
      console.error('Sportradar fallback also failed:', error.message);
    }
    
    return { playerName, found: false, source: 'all_failed' };
  }

  async findPlayerInRapidAPI(playerName) {
    // Only use if you have a RapidAPI NBA stats subscription
    if (!this.rapidapiKey) return null;
    
    try {
      const options = {
        method: 'GET',
        url: 'https://api-nba-v1.p.rapidapi.com/players',
        params: { search: playerName },
        headers: {
          'x-rapidapi-key': this.rapidapiKey,
          'x-rapidapi-host': 'api-nba-v1.p.rapidapi.com'
        }
      };
      
      const response = await axios.request(options);
      if (response.data.response?.length > 0) {
        return response.data.response[0].id;
      }
    } catch (error) {
      console.error('RapidAPI search failed:', error.message);
    }
    
    return null;
  }

  /**
   * Get today's NBA games
   */
  async getTodaysGames() {
    try {
      const today = new Date().toISOString().split('T')[0];
      const gamesUrl = `http://data.nba.net/data/10s/prod/v1/${today}/scoreboard.json`;
      const response = await axios.get(gamesUrl);
      
      return response.data.games?.map(game => ({
        id: game.gameId,
        homeTeam: game.hTeam.triCode,
        awayTeam: game.vTeam.triCode,
        startTime: game.startTimeUTC,
        status: game.statusNum
      })) || [];
      
    } catch (error) {
      console.error('NBA Data API games error:', error.message);
      return [];
    }
  }

  /**
   * Get NBA teams
   */
  async getNBATeams() {
    try {
      const teamsUrl = 'http://data.nba.net/data/10s/prod/v1/2024/teams.json';
      const response = await axios.get(teamsUrl);
      return response.data.league?.standard || [];
    } catch (error) {
      console.error('NBA Data API teams error:', error.message);
      return [];
    }
  }

  /**
   * Get NBA schedule for a specific date
   */
  async getScheduleForDate(date) {
    try {
      const scheduleUrl = `http://data.nba.net/data/10s/prod/v1/${date}/scoreboard.json`;
      const response = await axios.get(scheduleUrl);
      return response.data.games || [];
    } catch (error) {
      console.error('NBA Data API schedule error:', error.message);
      return [];
    }
  }
}

// Export as ES6 module
export default new NBAApiService();
