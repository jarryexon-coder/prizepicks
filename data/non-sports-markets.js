// data/non-sports-markets.js
// Curated non-sports prediction markets from Kalshi-like data

export const NON_SPORTS_MARKETS = {
  politics: [
    {
      id: 'pol-fed-rates-2026',
      question: 'Will the Federal Reserve cut interest rates by June 2026?',
      category: 'Politics',
      yesPrice: '0.62',
      noPrice: '0.38',
      volume: '$4.2M',
      analysis: 'Recent inflation data shows cooling trends. Fed futures indicate 65% probability of rate cuts by June.',
      expires: '2026-06-30',
      confidence: 74,
      platform: 'kalshi'
    },
    {
      id: 'pol-house-2026',
      question: 'Will the Democratic party win control of the House in 2026?',
      category: 'Politics',
      yesPrice: '0.48',
      noPrice: '0.52',
      volume: '$8.7M',
      analysis: 'Historical midterm trends favor opposition party. Current polling shows a tight race in key districts.',
      expires: '2026-11-15',
      confidence: 68,
      platform: 'kalshi'
    },
    {
      id: 'pol-government-shutdown',
      question: 'Will there be a government shutdown in 2026?',
      category: 'Politics',
      yesPrice: '0.35',
      noPrice: '0.65',
      volume: '$3.1M',
      analysis: 'Bipartisan budget talks ongoing. Markets see 35% chance of shutdown by end of fiscal year.',
      expires: '2026-09-30',
      confidence: 71,
      platform: 'kalshi'
    },
    {
      id: 'pol-climate-bill',
      question: 'Will the US pass a new climate bill in 2026?',
      category: 'Politics',
      yesPrice: '0.42',
      noPrice: '0.58',
      volume: '$2.3M',
      analysis: 'Limited legislative window before midterms. Moderate probability of bipartisan energy package.',
      expires: '2026-12-31',
      confidence: 65,
      platform: 'kalshi'
    }
  ],
  economics: [
    {
      id: 'eco-sp500-6000',
      question: 'Will the S&P 500 reach 6000 by end of 2026?',
      category: 'Economics',
      yesPrice: '0.45',
      noPrice: '0.55',
      volume: '$12.4M',
      analysis: 'Corporate earnings remain strong. Historical patterns suggest continued growth potential.',
      expires: '2026-12-31',
      confidence: 62,
      platform: 'kalshi'
    },
    {
      id: 'eco-bitcoin-100k',
      question: 'Will Bitcoin exceed $100,000 in 2026?',
      category: 'Economics',
      yesPrice: '0.38',
      noPrice: '0.62',
      volume: '$9.8M',
      analysis: 'Institutional adoption increasing but regulatory uncertainty remains.',
      expires: '2026-12-31',
      confidence: 58,
      platform: 'kalshi'
    },
    {
      id: 'eco-unemployment',
      question: 'Will the US unemployment rate drop below 3.5% in 2026?',
      category: 'Economics',
      yesPrice: '0.51',
      noPrice: '0.49',
      volume: '$5.6M',
      analysis: 'Labor market remains tight but showing signs of moderation.',
      expires: '2026-12-31',
      confidence: 66,
      platform: 'kalshi'
    }
  ],
  technology: [
    {
      id: 'tech-apple-foldable',
      question: 'Will Apple announce a foldable iPhone in 2026?',
      category: 'Technology',
      yesPrice: '0.44',
      noPrice: '0.56',
      volume: '$7.2M',
      analysis: 'Supply chain leaks indicate active development. Patent filings confirm foldable research.',
      expires: '2026-12-31',
      confidence: 68,
      platform: 'kalshi'
    },
    {
      id: 'tech-tesla-fsd',
      question: 'Will Tesla achieve Level 5 autonomy by end of 2026?',
      category: 'Technology',
      yesPrice: '0.28',
      noPrice: '0.72',
      volume: '$6.5M',
      analysis: 'Regulatory hurdles and technical challenges remain significant.',
      expires: '2026-12-31',
      confidence: 55,
      platform: 'kalshi'
    },
    {
      id: 'tech-quantum-supremacy',
      question: 'Will quantum computing achieve supremacy in 2026?',
      category: 'Technology',
      yesPrice: '0.31',
      noPrice: '0.69',
      volume: '$3.8M',
      analysis: 'Multiple breakthroughs needed. Experts suggest 2027-2028 more realistic.',
      expires: '2026-12-31',
      confidence: 54,
      platform: 'kalshi'
    }
  ],
  entertainment: [
    {
      id: 'ent-taylor-grammy',
      question: 'Will Taylor Swift win Album of the Year at the 2027 Grammys?',
      category: 'Entertainment',
      yesPrice: '0.72',
      noPrice: '0.28',
      volume: '$4.1M',
      analysis: 'Critical acclaim and commercial success make her a strong favorite.',
      expires: '2027-02-15',
      confidence: 76,
      platform: 'kalshi'
    },
    {
      id: 'ent-dune-vfx',
      question: 'Will Dune: Messiah win Best Visual Effects at 2027 Oscars?',
      category: 'Entertainment',
      yesPrice: '0.68',
      noPrice: '0.32',
      volume: '$2.9M',
      analysis: 'First film won category. Sequel expected to be visually spectacular.',
      expires: '2027-03-01',
      confidence: 72,
      platform: 'kalshi'
    }
  ],
  health: [
    {
      id: 'health-alzheimers',
      question: 'Will FDA approve a new Alzheimer\'s treatment in 2026?',
      category: 'Health',
      yesPrice: '0.59',
      noPrice: '0.41',
      volume: '$5.3M',
      analysis: 'Phase 3 trials show promising results. Fast-track designation granted.',
      expires: '2026-12-31',
      confidence: 71,
      platform: 'kalshi'
    }
  ],
  weather: [
    {
      id: 'weather-hurricane',
      question: 'Will a Category 4+ hurricane hit the US mainland in 2026?',
      category: 'Weather',
      yesPrice: '0.34',
      noPrice: '0.66',
      volume: '$3.2M',
      analysis: 'El Niño pattern may suppress Atlantic hurricane activity.',
      expires: '2026-11-30',
      confidence: 69,
      platform: 'kalshi'
    }
  ]
};

export const getAllNonSportsMarkets = () => {
  const all = [];
  for (const category in NON_SPORTS_MARKETS) {
    all.push(...NON_SPORTS_MARKETS[category]);
  }
  return all;
};
