/**
 * @jest-environment jsdom
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SummaryPanel from '../src/app/components/SummaryPanel';

// Mock assessment result data
const mockAssessmentResult = {
  summary: {
    total: 10,
    positive: 2,
    suspected: 1,
    abstain: 5,
    na: 2,
    confirmed_probe: 1,
    confirmed_ml_inject: 1
  },
  meta: {
    endpoints_supplied: 5,
    targets_enumerated: 8,
    processing_time: "1.2s",
    probe_attempts: 3,
    probe_successes: 1,
    ml_inject_attempts: 5,
    ml_inject_successes: 1,
    strategy: "ml_with_context",
    counters_consistent: true,
    violations: []
  },
  results: [
    { decision: "positive", rank_source: "probe_only", family: "xss" },
    { decision: "positive", rank_source: "ml", family: "sqli" },
    { decision: "suspected", rank_source: "ml", family: "xss" },
    { decision: "abstain", rank_source: "ml", family: "redirect" },
    { decision: "abstain", rank_source: "ml", family: "xss" },
    { decision: "abstain", rank_source: "ml", family: "sqli" },
    { decision: "abstain", rank_source: "ml", family: "redirect" },
    { decision: "abstain", rank_source: "ml", family: "xss" },
    { decision: "not_applicable", rank_source: "none", family: null },
    { decision: "not_applicable", rank_source: "none", family: null }
  ]
};

const mockAssessmentResultWithViolations = {
  ...mockAssessmentResult,
  meta: {
    ...mockAssessmentResult.meta,
    counters_consistent: false,
    violations: ["strategy_violation:probe_positive_under_ml_only"]
  }
};

describe('SummaryPanel', () => {
  test('renders summary counts from backend data', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    // Check that summary counts are displayed
    expect(screen.getByText('Endpoints crawled')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument(); // endpoints_supplied
    
    expect(screen.getByText('Targets enumerated')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument(); // targets_enumerated
    
    expect(screen.getByText('Confirmed (Probe)')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument(); // confirmed_probe
    
    expect(screen.getByText('Confirmed (ML+Inject)')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument(); // confirmed_ml_inject
  });
  
  test('shows strategy badge for ml_with_context', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    expect(screen.getByText('Strategy: ml_with_context')).toBeInTheDocument();
  });
  
  test('shows counters inconsistency warning when counters_consistent is false', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResultWithViolations}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('⚠️ Counters Inconsistent')).toBeInTheDocument();
    expect(screen.getByText('Event counters don\'t match table rows. Check server logs for details.')).toBeInTheDocument();
  });
  
  test('shows strategy violation alert when violations exist', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResultWithViolations}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('⚠️ Strategy Violation')).toBeInTheDocument();
    expect(screen.getByText('strategy_violation:probe_positive_under_ml_only')).toBeInTheDocument();
  });
  
  test('does not show counters inconsistency warning when counters_consistent is true', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    expect(screen.queryByText('⚠️ Counters Inconsistent')).not.toBeInTheDocument();
  });
  
  test('shows ML mode badge', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    expect(screen.getByText('ML: Calibrated models')).toBeInTheDocument();
  });
});
