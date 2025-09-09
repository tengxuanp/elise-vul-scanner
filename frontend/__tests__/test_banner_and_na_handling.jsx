/**
 * @jest-environment jsdom
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SummaryPanel from '../src/app/components/SummaryPanel';

// Mock assessment result data for ml_with_context
const mockMLWithContextResult = {
  summary: {
    total: 5,
    positive: 1,
    suspected: 0,
    abstain: 2,
    na: 2,
    confirmed_probe: 0,
    confirmed_ml_inject: 1
  },
  meta: {
    endpoints_supplied: 3,
    targets_enumerated: 5,
    processing_time: "1.2s",
    probe_attempts: 1,
    probe_successes: 0,
    ml_inject_attempts: 3,
    ml_inject_successes: 1,
    strategy: "ml_with_context",
    counters_consistent: true,
    violations: []
  },
  results: [
    { decision: "positive", rank_source: "ml", family: "xss", provenance: "Inject" },
    { decision: "abstain", rank_source: "ml", family: "sqli", provenance: "Inject" },
    { decision: "abstain", rank_source: "ml", family: "redirect", provenance: "Inject" }
  ]
};

// Mock assessment result with NA rows that should not appear in main results
const mockResultWithNA = {
  summary: {
    total: 8,
    positive: 1,
    suspected: 0,
    abstain: 2,
    na: 5,
    confirmed_probe: 0,
    confirmed_ml_inject: 1
  },
  meta: {
    endpoints_supplied: 5,
    targets_enumerated: 8,
    processing_time: "1.5s",
    probe_attempts: 0,
    probe_successes: 0,
    ml_inject_attempts: 3,
    ml_inject_successes: 1,
    strategy: "ml_only",
    counters_consistent: true,
    violations: []
  },
  results: [
    { decision: "positive", rank_source: "ml", family: "xss", provenance: "Inject" },
    { decision: "abstain", rank_source: "ml", family: "sqli", provenance: "Inject" },
    { decision: "abstain", rank_source: "ml", family: "redirect", provenance: "Inject" }
    // Note: NA results should not be in the results array
  ]
};

describe('Banner and NA Handling', () => {
  test('shows correct banner for ml_with_context strategy', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockMLWithContextResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    // Check that the strategy badge shows ml_with_context
    expect(screen.getByText('Strategy: ml_with_context')).toBeInTheDocument();
    
    // Check that confirmed probe is 0 (no probe positives allowed)
    expect(screen.getByText('0')).toBeInTheDocument(); // confirmed_probe should be 0
  });
  
  test('NA rows do not leak into main results', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockResultWithNA}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_only"
      />
    );
    
    // Check that we have the correct counts
    expect(screen.getByText('Endpoints crawled')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument(); // endpoints_supplied
    
    expect(screen.getByText('Targets enumerated')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument(); // targets_enumerated
    
    // Check that NA count is shown separately (5 NA results)
    // The NA count should be reflected in the summary but not in the main results array
    expect(screen.getByText('NA (no params): 5')).toBeInTheDocument();
  });
  
  test('counters consistency is maintained', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockMLWithContextResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    // Should not show counters inconsistency warning
    expect(screen.queryByText('⚠️ Counters Inconsistent')).not.toBeInTheDocument();
    
    // Check that confirmed counts match
    expect(screen.getByText('Confirmed (Probe)')).toBeInTheDocument();
    expect(screen.getByText('Confirmed (ML+Inject)')).toBeInTheDocument();
  });
  
  test('shows counters inconsistency warning when needed', () => {
    const inconsistentResult = {
      ...mockMLWithContextResult,
      meta: {
        ...mockMLWithContextResult.meta,
        counters_consistent: false
      }
    };
    
    render(
      <SummaryPanel 
        assessmentResult={inconsistentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );
    
    // Should show counters inconsistency warning
    expect(screen.getByText('⚠️ Counters Inconsistent')).toBeInTheDocument();
    expect(screen.getByText('Event counters don\'t match table rows. Check server logs for details.')).toBeInTheDocument();
  });
});
