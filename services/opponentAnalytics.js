// services/opponentAnalytics.js
// Advanced opponent analytics for NBA, NHL, and MLB
// Computes defensive averages and matchup advantages

class OpponentAnalytics {
  constructor() {
    // Cache for opponent stats
    this.opponentStatsCache = new Map();
    this.lastUpdated = null;
  }

  // ==================== NBA OPPONENT ANALYTICS ====================
  
  // NBA defensive stats by team (points allowed, rebounds allowed, etc.)
  getNBADefensiveStats() {
    // 2025-26 NBA regular season defensive averages
    // These represent points/rebounds/assists allowed per game
    return {
      'ATL': { ptsAllowed: 120.1, rebAllowed: 44.2, astAllowed: 27.5, fgPctAllowed: 48.2, threePmAllowed: 13.5 },
      'BOS': { ptsAllowed: 109.8, rebAllowed: 42.1, astAllowed: 24.2, fgPctAllowed: 45.1, threePmAllowed: 11.2 },
      'CLE': { ptsAllowed: 110.5, rebAllowed: 43.0, astAllowed: 25.0, fgPctAllowed: 46.5, threePmAllowed: 12.0 },
      'DEN': { ptsAllowed: 112.5, rebAllowed: 43.5, astAllowed: 26.0, fgPctAllowed: 47.0, threePmAllowed: 12.5 },
      'DET': { ptsAllowed: 113.8, rebAllowed: 44.0, astAllowed: 26.5, fgPctAllowed: 47.5, threePmAllowed: 13.0 },
      'HOU': { ptsAllowed: 114.5, rebAllowed: 44.5, astAllowed: 27.0, fgPctAllowed: 48.0, threePmAllowed: 13.2 },
      'LAL': { ptsAllowed: 115.5, rebAllowed: 45.0, astAllowed: 27.5, fgPctAllowed: 48.5, threePmAllowed: 13.8 },
      'MIN': { ptsAllowed: 108.5, rebAllowed: 41.5, astAllowed: 24.0, fgPctAllowed: 44.5, threePmAllowed: 11.0 },
      'NYK': { ptsAllowed: 109.5, rebAllowed: 42.0, astAllowed: 24.5, fgPctAllowed: 45.0, threePmAllowed: 11.5 },
      'OKC': { ptsAllowed: 106.5, rebAllowed: 41.0, astAllowed: 23.5, fgPctAllowed: 44.0, threePmAllowed: 10.5 },
      'ORL': { ptsAllowed: 108.5, rebAllowed: 42.5, astAllowed: 24.0, fgPctAllowed: 45.5, threePmAllowed: 11.0 },
      'PHI': { ptsAllowed: 113.5, rebAllowed: 44.0, astAllowed: 26.0, fgPctAllowed: 47.5, threePmAllowed: 12.8 },
      'PHX': { ptsAllowed: 115.5, rebAllowed: 45.5, astAllowed: 27.5, fgPctAllowed: 48.5, threePmAllowed: 13.5 },
      'POR': { ptsAllowed: 115.5, rebAllowed: 45.0, astAllowed: 27.0, fgPctAllowed: 48.0, threePmAllowed: 13.5 },
      'SAS': { ptsAllowed: 115.5, rebAllowed: 45.0, astAllowed: 28.0, fgPctAllowed: 48.0, threePmAllowed: 13.0 },
      'TOR': { ptsAllowed: 115.5, rebAllowed: 44.5, astAllowed: 27.5, fgPctAllowed: 48.0, threePmAllowed: 13.0 }
    };
  }

  // Calculate matchup advantage for NBA player
  calculateNBAMatchup(player, opponentTeam) {
    const defensiveStats = this.getNBADefensiveStats();
    const oppDefense = defensiveStats[opponentTeam];
    
    if (!oppDefense) {
      return { multiplier: 1.0, edge: 0, analysis: 'League average opponent' };
    }
    
    // Calculate league averages
    const leagueAvgPts = 112.5;
    const leagueAvgReb = 43.5;
    const leagueAvgAst = 26.0;
    
    // Calculate multipliers based on opponent's defensive weakness
    let ptsMultiplier = 1.0;
    let rebMultiplier = 1.0;
    let astMultiplier = 1.0;
    
    // Points adjustment
    if (oppDefense.ptsAllowed > leagueAvgPts) {
      ptsMultiplier = 1 + ((oppDefense.ptsAllowed - leagueAvgPts) / leagueAvgPts) * 0.5;
    } else if (oppDefense.ptsAllowed < leagueAvgPts) {
      ptsMultiplier = 1 - ((leagueAvgPts - oppDefense.ptsAllowed) / leagueAvgPts) * 0.3;
    }
    
    // Rebounds adjustment
    if (oppDefense.rebAllowed > leagueAvgReb) {
      rebMultiplier = 1 + ((oppDefense.rebAllowed - leagueAvgReb) / leagueAvgReb) * 0.4;
    } else if (oppDefense.rebAllowed < leagueAvgReb) {
      rebMultiplier = 1 - ((leagueAvgReb - oppDefense.rebAllowed) / leagueAvgReb) * 0.3;
    }
    
    // Assists adjustment
    if (oppDefense.astAllowed > leagueAvgAst) {
      astMultiplier = 1 + ((oppDefense.astAllowed - leagueAvgAst) / leagueAvgAst) * 0.4;
    } else if (oppDefense.astAllowed < leagueAvgAst) {
      astMultiplier = 1 - ((leagueAvgAst - oppDefense.astAllowed) / leagueAvgAst) * 0.3;
    }
    
    const overallMultiplier = (ptsMultiplier + rebMultiplier + astMultiplier) / 3;
    const edge = (overallMultiplier - 1) * 100;
    
    let analysis = '';
    if (edge > 5) analysis = `Great matchup - ${opponentTeam} allows ${(oppDefense.ptsAllowed - leagueAvgPts).toFixed(1)} more points than league average`;
    else if (edge < -5) analysis = `Tough matchup - ${opponentTeam} allows ${(leagueAvgPts - oppDefense.ptsAllowed).toFixed(1)} fewer points than league average`;
    else analysis = `Average matchup against ${opponentTeam}`;
    
    return {
      multiplier: overallMultiplier,
      edge: edge,
      analysis: analysis,
      detailed: {
        points: ptsMultiplier,
        rebounds: rebMultiplier,
        assists: astMultiplier
      }
    };
  }

  // ==================== NHL OPPONENT ANALYTICS ====================
  
  getNHLDefensiveStats() {
    // 2025-26 NHL defensive averages (goals against, shots against, etc.)
    return {
      'BOS': { goalsAgainst: 2.65, shotsAgainst: 28.5, penaltyKill: 84.2 },
      'CAR': { goalsAgainst: 2.58, shotsAgainst: 27.8, penaltyKill: 85.1 },
      'COL': { goalsAgainst: 2.85, shotsAgainst: 29.5, penaltyKill: 82.5 },
      'DAL': { goalsAgainst: 2.62, shotsAgainst: 28.2, penaltyKill: 83.8 },
      'EDM': { goalsAgainst: 2.95, shotsAgainst: 30.2, penaltyKill: 80.5 },
      'FLA': { goalsAgainst: 2.55, shotsAgainst: 27.5, penaltyKill: 85.5 },
      'MIN': { goalsAgainst: 2.70, shotsAgainst: 28.8, penaltyKill: 83.0 },
      'NJD': { goalsAgainst: 2.68, shotsAgainst: 28.0, penaltyKill: 84.0 },
      'NYR': { goalsAgainst: 2.72, shotsAgainst: 28.5, penaltyKill: 83.5 },
      'TOR': { goalsAgainst: 2.88, shotsAgainst: 29.8, penaltyKill: 81.5 },
      'VAN': { goalsAgainst: 2.75, shotsAgainst: 29.0, penaltyKill: 82.5 },
      'VGK': { goalsAgainst: 2.60, shotsAgainst: 27.5, penaltyKill: 84.5 }
    };
  }

  calculateNHLMatchup(player, opponentTeam, statType = 'goals') {
    const defensiveStats = this.getNHLDefensiveStats();
    const oppDefense = defensiveStats[opponentTeam];
    
    if (!oppDefense) {
      return { multiplier: 1.0, edge: 0, analysis: 'League average opponent' };
    }
    
    const leagueAvgGoalsAgainst = 2.75;
    const leagueAvgShotsAgainst = 28.7;
    
    let multiplier = 1.0;
    let analysis = '';
    
    if (statType === 'goals' || statType === 'points') {
      if (oppDefense.goalsAgainst > leagueAvgGoalsAgainst) {
        multiplier = 1 + ((oppDefense.goalsAgainst - leagueAvgGoalsAgainst) / leagueAvgGoalsAgainst) * 0.6;
        analysis = `Favorable - ${opponentTeam} allows ${(oppDefense.goalsAgainst - leagueAvgGoalsAgainst).toFixed(2)} more goals per game`;
      } else if (oppDefense.goalsAgainst < leagueAvgGoalsAgainst) {
        multiplier = 1 - ((leagueAvgGoalsAgainst - oppDefense.goalsAgainst) / leagueAvgGoalsAgainst) * 0.4;
        analysis = `Tough matchup - ${opponentTeam} allows ${(leagueAvgGoalsAgainst - oppDefense.goalsAgainst).toFixed(2)} fewer goals per game`;
      } else {
        analysis = `Average matchup against ${opponentTeam}`;
      }
    } else if (statType === 'shots') {
      if (oppDefense.shotsAgainst > leagueAvgShotsAgainst) {
        multiplier = 1 + ((oppDefense.shotsAgainst - leagueAvgShotsAgainst) / leagueAvgShotsAgainst) * 0.5;
        analysis = `Favorable - ${opponentTeam} allows ${(oppDefense.shotsAgainst - leagueAvgShotsAgainst).toFixed(1)} more shots per game`;
      } else {
        multiplier = 1 - ((leagueAvgShotsAgainst - oppDefense.shotsAgainst) / leagueAvgShotsAgainst) * 0.3;
        analysis = `Tough matchup - ${opponentTeam} allows fewer shots`;
      }
    }
    
    const edge = (multiplier - 1) * 100;
    
    return {
      multiplier: multiplier,
      edge: edge,
      analysis: analysis,
      statType: statType
    };
  }

  // ==================== MLB OPPONENT ANALYTICS ====================
  
  getMLBDefensiveStats() {
    // 2025-26 MLB defensive/pitching stats
    return {
      'ARI': { era: 4.25, whip: 1.32, kPer9: 8.5, hrAllowed: 1.2 },
      'ATL': { era: 3.85, whip: 1.22, kPer9: 9.2, hrAllowed: 1.0 },
      'BAL': { era: 4.05, whip: 1.28, kPer9: 8.8, hrAllowed: 1.1 },
      'BOS': { era: 4.15, whip: 1.30, kPer9: 8.6, hrAllowed: 1.1 },
      'CLE': { era: 3.95, whip: 1.25, kPer9: 8.9, hrAllowed: 1.0 },
      'HOU': { era: 3.75, whip: 1.20, kPer9: 9.5, hrAllowed: 0.9 },
      'KC': { era: 4.10, whip: 1.28, kPer9: 8.4, hrAllowed: 1.1 },
      'LAD': { era: 3.65, whip: 1.18, kPer9: 9.8, hrAllowed: 0.9 },
      'NYM': { era: 4.00, whip: 1.27, kPer9: 8.7, hrAllowed: 1.1 },
      'NYY': { era: 3.80, whip: 1.22, kPer9: 9.3, hrAllowed: 1.0 },
      'PHI': { era: 3.90, whip: 1.24, kPer9: 9.0, hrAllowed: 1.0 },
      'SD': { era: 3.95, whip: 1.25, kPer9: 8.9, hrAllowed: 1.0 },
      'STL': { era: 4.00, whip: 1.27, kPer9: 8.6, hrAllowed: 1.1 },
      'TEX': { era: 3.85, whip: 1.23, kPer9: 9.1, hrAllowed: 1.0 }
    };
  }

  calculateMLBMatchup(player, opponentTeam, statType = 'hits') {
    const pitchingStats = this.getMLBDefensiveStats();
    const oppPitching = pitchingStats[opponentTeam];
    
    if (!oppPitching) {
      return { multiplier: 1.0, edge: 0, analysis: 'League average opponent' };
    }
    
    const leagueAvgEra = 3.95;
    const leagueAvgWhip = 1.25;
    const leagueAvgKPer9 = 8.9;
    const leagueAvgHrAllowed = 1.05;
    
    let multiplier = 1.0;
    let analysis = '';
    
    if (statType === 'hits') {
      if (oppPitching.whip > leagueAvgWhip) {
        multiplier = 1 + ((oppPitching.whip - leagueAvgWhip) / leagueAvgWhip) * 0.5;
        analysis = `Favorable - ${opponentTeam} has ${(oppPitching.whip - leagueAvgWhip).toFixed(2)} higher WHIP than league avg`;
      } else {
        multiplier = 1 - ((leagueAvgWhip - oppPitching.whip) / leagueAvgWhip) * 0.3;
        analysis = `Tough matchup - ${opponentTeam} has strong pitching`;
      }
    } else if (statType === 'home_runs') {
      if (oppPitching.hrAllowed > leagueAvgHrAllowed) {
        multiplier = 1 + ((oppPitching.hrAllowed - leagueAvgHrAllowed) / leagueAvgHrAllowed) * 0.6;
        analysis = `Favorable - ${opponentTeam} allows ${(oppPitching.hrAllowed - leagueAvgHrAllowed).toFixed(1)} more HR per game`;
      } else {
        multiplier = 1 - ((leagueAvgHrAllowed - oppPitching.hrAllowed) / leagueAvgHrAllowed) * 0.4;
        analysis = `Tough - ${opponentTeam} allows fewer home runs`;
      }
    } else if (statType === 'rbi') {
      if (oppPitching.era > leagueAvgEra) {
        multiplier = 1 + ((oppPitching.era - leagueAvgEra) / leagueAvgEra) * 0.5;
        analysis = `Favorable - ${opponentTeam} has ${(oppPitching.era - leagueAvgEra).toFixed(2)} higher ERA`;
      } else {
        multiplier = 1 - ((leagueAvgEra - oppPitching.era) / leagueAvgEra) * 0.3;
        analysis = `Tough matchup against good pitching`;
      }
    }
    
    const edge = (multiplier - 1) * 100;
    
    return {
      multiplier: multiplier,
      edge: edge,
      analysis: analysis,
      statType: statType
    };
  }

  // ==================== GENERAL METHODS ====================
  
  // Get opponent team for a player based on today's schedule
  getOpponentForPlayer(playerTeam, games) {
    const game = games.find(g => g.away === playerTeam || g.home === playerTeam);
    if (!game) return null;
    return game.away === playerTeam ? game.home : game.away;
  }

  // Apply matchup adjustments to a player's projection
  applyMatchupAdjustment(projection, matchup, statType = null) {
    if (!matchup || matchup.multiplier === 1.0) {
      return {
        adjustedProjection: projection,
        adjustmentFactor: 1.0,
        edge: 0
      };
    }
    
    const adjustedProjection = projection * matchup.multiplier;
    const edge = ((adjustedProjection - projection) / projection) * 100;
    
    return {
      adjustedProjection: parseFloat(adjustedProjection.toFixed(1)),
      adjustmentFactor: matchup.multiplier,
      edge: parseFloat(edge.toFixed(1)),
      analysis: matchup.analysis
    };
  }

  // Generate a complete matchup report for a player
  getMatchupReport(player, playerTeam, opponentTeam, sport, statType = null) {
    let matchup;
    
    switch(sport) {
      case 'nba':
        matchup = this.calculateNBAMatchup(player, opponentTeam);
        break;
      case 'nhl':
        matchup = this.calculateNHLMatchup(player, opponentTeam, statType);
        break;
      case 'mlb':
        matchup = this.calculateMLBMatchup(player, opponentTeam, statType);
        break;
      default:
        matchup = { multiplier: 1.0, edge: 0, analysis: 'No matchup data available' };
    }
    
    return {
      player: player.name,
      team: playerTeam,
      opponent: opponentTeam,
      sport: sport,
      matchupAnalysis: matchup.analysis,
      adjustmentMultiplier: matchup.multiplier,
      projectedEdge: matchup.edge,
      timestamp: new Date().toISOString()
    };
  }

  // Clear cache (useful for refreshing data)
  clearCache() {
    this.opponentStatsCache.clear();
    this.lastUpdated = null;
    console.log('🔄 Opponent analytics cache cleared');
  }
}

// Export singleton instance
export default new OpponentAnalytics();
