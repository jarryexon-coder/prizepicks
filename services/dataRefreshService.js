// services/dataRefreshService.js
// Automated data refresh service for NBA, NHL, MLB stats

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class DataRefreshService {
  constructor() {
    this.refreshInterval = null;
    this.lastRefresh = null;
    this.isRefreshing = false;
  }

  // Start automatic refresh schedule
  startAutoRefresh(intervalMinutes = 60) {
    console.log(`🔄 Starting auto-refresh every ${intervalMinutes} minutes`);
    
    // Run immediately on start
    this.refreshAllData();
    
    // Schedule regular updates
    this.refreshInterval = setInterval(() => {
      this.refreshAllData();
    }, intervalMinutes * 60 * 1000);
  }

  // Stop auto-refresh
  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
      console.log('🛑 Auto-refresh stopped');
    }
  }

  // Main refresh function
  async refreshAllData() {
    if (this.isRefreshing) {
      console.log('⏳ Refresh already in progress, skipping...');
      return;
    }

    this.isRefreshing = true;
    console.log('🔄 Starting data refresh...');
    const startTime = Date.now();

    try {
      // Refresh all sports
      await Promise.all([
        this.refreshNBAData(),
        this.refreshNHLData(),
        this.refreshMLBData()
      ]);

      this.lastRefresh = new Date();
      const duration = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`✅ Data refresh complete in ${duration}s`);

    } catch (error) {
      console.error('❌ Data refresh failed:', error);
    } finally {
      this.isRefreshing = false;
    }
  }

  // Refresh NBA data
  async refreshNBAData() {
    console.log('🏀 Refreshing NBA data...');
    
    try {
      // Fetch from your Python API
      const pythonApiUrl = process.env.PYTHON_API_URL || 'https://python-api-fresh-production.up.railway.app';
      const response = await fetch(`${pythonApiUrl}/api/fantasy/players?realtime=true&sport=nba`);
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      
      if (data.success && data.players) {
        // Transform to your format
        const updatedPlayers = data.players.map(p => ({
          name: p.name,
          team: p.team,
          position: p.position,
          points: p.points || 0,
          rebounds: p.rebounds || 0,
          assists: p.assists || 0,
          steals: p.steals || 0,
          blocks: p.blocks || 0,
          fantasy_points: p.fantasy_points || 0,
          injury_status: p.injury_status || 'Active',
          last_updated: new Date().toISOString()
        }));
        
        // Save to file
        await this.saveToFile('nba-playoffs-2026', updatedPlayers);
        console.log(`✅ Saved ${updatedPlayers.length} NBA players`);
        return updatedPlayers;
      }
    } catch (error) {
      console.error('NBA refresh failed:', error.message);
      return null;
    }
  }

  // Refresh NHL data
  async refreshNHLData() {
    console.log('🏒 Refreshing NHL data...');
    
    try {
      // NHL API (free, no key required)
      const response = await fetch('https://statsapi.web.nhl.com/api/v1/teams');
      const data = await response.json();
      
      const playoffTeams = ['BOS', 'COL', 'DAL', 'EDM', 'FLA', 'NYR', 'TOR', 'VGK'];
      const players = [];
      
      for (const team of data.teams) {
        if (playoffTeams.includes(team.abbreviation)) {
          const rosterRes = await fetch(`https://statsapi.web.nhl.com/api/v1/teams/${team.id}/roster`);
          const roster = await rosterRes.json();
          
          for (const player of roster.roster) {
            // Get player stats
            const statsRes = await fetch(`https://statsapi.web.nhl.com/api/v1/people/${player.person.id}/stats?stats=statsSingleSeason&season=20252026`);
            const stats = await statsRes.json();
            const seasonStats = stats.stats?.[0]?.splits?.[0]?.stat || {};
            
            players.push({
              name: player.person.fullName,
              team: team.abbreviation,
              position: player.position.code,
              goals: seasonStats.goals || 0,
              assists: seasonStats.assists || 0,
              shots: seasonStats.shots || 0,
              fantasy_points: (seasonStats.goals || 0) * 3 + (seasonStats.assists || 0) * 2 + (seasonStats.shots || 0) * 0.5,
              injury_status: 'Active',
              last_updated: new Date().toISOString()
            });
          }
        }
      }
      
      await this.saveToFile('nhl-players', players);
      console.log(`✅ Saved ${players.length} NHL players`);
      return players;
      
    } catch (error) {
      console.error('NHL refresh failed:', error.message);
      return null;
    }
  }

  // Refresh MLB data
  async refreshMLBData() {
    console.log('⚾ Refreshing MLB data...');
    
    try {
      // MLB Stats API
      const response = await fetch('https://statsapi.mlbucky.com/api/v1/sports/1/players');
      const data = await response.json();
      
      const playoffTeams = ['NYY', 'HOU', 'LAD', 'ATL', 'PHI', 'SD', 'TEX', 'BAL'];
      const players = [];
      
      for (const player of data.players || []) {
        if (playoffTeams.includes(player.currentTeam?.abbreviation)) {
          players.push({
            name: `${player.firstName} ${player.lastName}`,
            team: player.currentTeam?.abbreviation,
            position: player.primaryPosition?.abbreviation,
            hits: player.stats?.hits || 0,
            hr: player.stats?.homeRuns || 0,
            rbi: player.stats?.rbi || 0,
            fantasy_points: (player.stats?.hits || 0) + (player.stats?.rbi || 0) + (player.stats?.homeRuns || 0) * 2,
            injury_status: player.injury?.status === 'ACTIVE' ? 'Active' : 'Active',
            last_updated: new Date().toISOString()
          });
        }
      }
      
      await this.saveToFile('mlb-players', players);
      console.log(`✅ Saved ${players.length} MLB players`);
      return players;
      
    } catch (error) {
      console.error('MLB refresh failed:', error.message);
      return null;
    }
  }

  // Save data to file
  async saveToFile(filename, data) {
    const filePath = path.join(__dirname, '..', 'data', `${filename}.js`);
    
    const fileContent = `// Auto-generated by DataRefreshService
// Last updated: ${new Date().toISOString()}
// DO NOT EDIT MANUALLY - Changes will be overwritten

export const ${filename.toUpperCase().replace(/-/g, '_')} = ${JSON.stringify(data, null, 2)};

export const ${filename.toUpperCase().replace(/-/g, '_')}_TEAMS = [...new Set(${JSON.stringify(data, null, 2)}.map(p => p.team))];

// Metadata
export const LAST_UPDATED = "${new Date().toISOString()}";
`;
    
    fs.writeFileSync(filePath, fileContent, 'utf8');
    console.log(`💾 Saved to ${filePath}`);
  }

  // Get refresh status
  getStatus() {
    return {
      isRefreshing: this.isRefreshing,
      lastRefresh: this.lastRefresh,
      refreshInterval: this.refreshInterval ? 'active' : 'stopped'
    };
  }
}

export default new DataRefreshService();
