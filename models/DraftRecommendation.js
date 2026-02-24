const mongoose = require('mongoose');

const DraftPickSchema = new mongoose.Schema({
  // Player Information
  playerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Player', required: true },
  playerName: { type: String, required: true },
  playerTeam: String,
  playerPosition: { type: String, required: true },
  
  // Draft Details
  round: { type: Number, required: true, min: 1 },
  pickNumber: { type: Number, required: true, min: 1 },
  overallPick: { type: Number, required: true, min: 1 },
  
  // Value & Pricing
  salary: { type: Number, required: true, min: 0 },
  valueScore: { type: Number, default: 0, min: 0, max: 100 },
  
  // Reasoning
  reasoning: { type: String, maxlength: 500 },
  keyFactors: [String],
});

const DraftRecommendationSchema = new mongoose.Schema({
  // Draft Configuration
  type: { type: String, enum: ['snake', 'turn'], required: true },
  sport: { type: String, enum: ['NBA', 'NHL', 'NFL', 'MLB'], required: true },
  draftPosition: { type: Number, required: true, min: 1 },
  totalTeams: { type: Number, default: 10 },
  totalRounds: { type: Number, default: 15 },
  platform: { type: String, default: 'FantasyHub' },
  scoringFormat: { type: String, default: 'standard' },
  
  // Draft Picks
  picks: [DraftPickSchema],
  
  // Performance Metrics
  totalValue: { type: Number, default: 0 },
  averagePickScore: { type: Number, default: 0, min: 0, max: 100 },
  
  // User Information
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  // Status
  status: { type: String, enum: ['completed', 'saved'], default: 'completed' },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });

// Pre-save hook to calculate totals
DraftRecommendationSchema.pre('save', function(next) {
  if (this.picks && this.picks.length > 0) {
    this.totalValue = this.picks.reduce((sum, pick) => sum + (pick.valueScore || 0), 0);
    this.averagePickScore = this.totalValue / this.picks.length;
  }
  next();
});

module.exports = mongoose.model('DraftRecommendation', DraftRecommendationSchema);
