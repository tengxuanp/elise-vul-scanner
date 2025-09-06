import React from 'react';

const MLScoreDisplay = ({ 
  ranker_meta, 
  family_probs, 
  used_path, 
  ranker_score,
  ml, // This is the key field from the backend
  family = 'sqli'
}) => {
  // Debug logging
  console.log('MLScoreDisplay props:', { ranker_meta, family_probs, used_path, ranker_score, ml, family });

  // Extract ML scores from ANY available source - be very aggressive
  const getMLScores = () => {
    // Priority 1: Direct ml field from backend (enhanced ML)
    if (ml && typeof ml === 'object') {
      if (ml.p !== undefined) {
        return {
          calibrated_probability: ml.p,
          confidence: ml.p, // Use p as confidence for now
          raw_probability: ml.p,
          uncertainty: 1 - ml.p,
          model_type: ml.source || 'enhanced_ml',
          is_enhanced: true,
          source: 'ml_field'
        };
      }
    }

    // Priority 2: ranker_meta field
    if (ranker_meta && typeof ranker_meta === 'object') {
      if (ranker_meta.calibrated_probability !== undefined) {
        return {
          calibrated_probability: ranker_meta.calibrated_probability,
          confidence: ranker_meta.confidence || ranker_meta.calibrated_probability,
          raw_probability: ranker_meta.raw_probability || ranker_meta.calibrated_probability,
          uncertainty: ranker_meta.uncertainty || (1 - (ranker_meta.confidence || ranker_meta.calibrated_probability)),
          model_type: ranker_meta.model_type || 'enhanced_ml',
          is_enhanced: true,
          source: 'ranker_meta'
        };
      }
      
      if (ranker_meta.confidence !== undefined) {
        return {
          calibrated_probability: ranker_meta.confidence,
          confidence: ranker_meta.confidence,
          raw_probability: ranker_meta.raw_probability || ranker_meta.confidence,
          uncertainty: ranker_meta.uncertainty || (1 - ranker_meta.confidence),
          model_type: ranker_meta.model_type || 'legacy_ml',
          is_enhanced: false,
          source: 'ranker_meta_confidence'
        };
      }
    }

    // Priority 3: family_probs
    if (family_probs && typeof family_probs === 'object') {
      const familyKey = family.toLowerCase();
      if (family_probs[familyKey] !== undefined) {
        return {
          calibrated_probability: family_probs[familyKey],
          confidence: family_probs[familyKey],
          raw_probability: family_probs[familyKey],
          uncertainty: 1 - family_probs[familyKey],
          model_type: 'family_probs',
          is_enhanced: false,
          source: 'family_probs'
        };
      }
    }

    // Priority 4: ranker_score
    if (ranker_score !== undefined && ranker_score !== null) {
      return {
        calibrated_probability: ranker_score,
        confidence: ranker_score,
        raw_probability: ranker_score,
        uncertainty: 1 - ranker_score,
        model_type: 'legacy_ranker',
        is_enhanced: false,
        source: 'ranker_score'
      };
    }

    // Priority 5: Check if used_path indicates ML was used
    if (used_path && (used_path.includes('ml') || used_path.includes('enhanced'))) {
      return {
        calibrated_probability: 0.0, // Default fallback
        confidence: 0.0,
        raw_probability: 0.0,
        uncertainty: 1.0,
        model_type: used_path,
        is_enhanced: used_path.includes('enhanced'),
        source: 'used_path_fallback'
      };
    }

    return null;
  };

  const scores = getMLScores();
  
  if (!scores) {
    return (
      <div className="text-xs text-gray-500 italic">
        No ML data available
      </div>
    );
  }

  // Format percentage with appropriate precision
  const formatPercentage = (value) => {
    if (value === 0) return '0.00%';
    if (value < 0.0001) return (value * 100).toFixed(6) + '%';
    if (value < 0.001) return (value * 100).toFixed(4) + '%';
    if (value < 0.01) return (value * 100).toFixed(3) + '%';
    return (value * 100).toFixed(2) + '%';
  };

  // Get color based on confidence level
  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    if (confidence >= 0.4) return 'text-orange-600';
    if (confidence >= 0.2) return 'text-red-600';
    return 'text-gray-600';
  };

  return (
    <div className="bg-blue-50 border border-blue-200 rounded p-3 space-y-2">
      <div className="text-xs font-semibold text-blue-800">
        ML Scores ({scores.source})
      </div>
      
      {/* Calibrated Probability */}
      <div className="flex justify-between items-center">
        <span className="text-xs text-gray-600">Calibrated Probability:</span>
        <span className={`text-sm font-bold ${getConfidenceColor(scores.calibrated_probability)}`}>
          {formatPercentage(scores.calibrated_probability)}
        </span>
      </div>

      {/* Confidence */}
      <div className="flex justify-between items-center">
        <span className="text-xs text-gray-600">Confidence:</span>
        <span className={`text-sm font-bold ${getConfidenceColor(scores.confidence)}`}>
          {formatPercentage(scores.confidence)}
        </span>
      </div>

      {/* Raw Probability */}
      <div className="flex justify-between items-center">
        <span className="text-xs text-gray-600">Raw Probability:</span>
        <span className="text-sm font-mono text-gray-700">
          {formatPercentage(scores.raw_probability)}
        </span>
      </div>

      {/* Uncertainty */}
      <div className="flex justify-between items-center">
        <span className="text-xs text-gray-600">Uncertainty:</span>
        <span className="text-sm font-mono text-gray-700">
          {formatPercentage(scores.uncertainty)}
        </span>
      </div>

      {/* Model Info */}
      <div className="text-xs text-gray-500 border-t pt-2">
        Model: {scores.model_type} | Enhanced: {scores.is_enhanced ? 'Yes' : 'No'}
      </div>
    </div>
  );
};

export default MLScoreDisplay;
