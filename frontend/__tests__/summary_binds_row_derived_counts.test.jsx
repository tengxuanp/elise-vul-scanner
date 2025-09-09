/**
 * Test that summary binds to row-derived counts.
 * Confirmed (ML) shows 4 when results contain 4 Inject positives.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SummaryPanel from '../src/app/components/SummaryPanel';

describe('SummaryPanel - Row Derived Counts', () => {
  test('Confirmed (ML) shows 4 when results contain 4 Inject positives', () => {
    const assessmentResult = {
      results: [
        { decision: "positive", provenance: "Inject", rank_source: "ctx_pool", family: "xss" },
        { decision: "positive", provenance: "Inject", rank_source: "ctx_pool", family: "xss" },
        { decision: "positive", provenance: "Inject", rank_source: "ctx_pool", family: "xss" },
        { decision: "positive", provenance: "Inject", rank_source: "ctx_pool", family: "xss" },
        { decision: "positive", provenance: "Probe", rank_source: "probe_only", family: "sqli" },
        { decision: "abstain", provenance: "Inject", rank_source: "ctx_pool", family: "xss" }
      ],
      summary: {
        confirmed_probe: 1,
        confirmed_ml_inject: 4,
        positive: 5,
        abstain: 1,
        na: 0
      },
      meta: {
        probe_attempts: 2,
        probe_successes: 1,
        ml_inject_attempts: 8,
        ml_inject_successes: 4,
        counters_consistent: true,
        processing_time: "1.2s"
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={assessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_with_context"
      />
    );

    // Check that Confirmed (ML+Inject) shows 4
    const confirmedML = screen.getByText('Confirmed (ML+Inject)');
    expect(confirmedML).toBeInTheDocument();
    
    // Check that Confirmed (ML+Inject) shows 4
    const confirmedMLValue = screen.getByText('Confirmed (ML+Inject)').parentElement.querySelector('.font-semibold.text-blue-600');
    expect(confirmedMLValue).toHaveTextContent('4');

    // Check that Confirmed (Probe) shows 1
    const confirmedProbe = screen.getByText('Confirmed (Probe)');
    expect(confirmedProbe).toBeInTheDocument();

    // Check that Total shows 6 (all results)
    const total = screen.getByText('Total');
    expect(total).toBeInTheDocument();
    
    // Check that the total value is 6
    const totalValue = screen.getByText('6');
    expect(totalValue).toBeInTheDocument();

    // Check that counters are consistent (no warning)
    expect(screen.queryByText('⚠️ Counters Inconsistent')).not.toBeInTheDocument();
  });

  test('Shows counters inconsistent warning when meta and summary don\'t match', () => {
    const assessmentResult = {
      results: [
        { decision: "positive", provenance: "Inject", rank_source: "ml", family: "xss" },
        { decision: "positive", provenance: "Inject", rank_source: "ml", family: "xss" }
      ],
      summary: {
        confirmed_probe: 0,
        confirmed_ml_inject: 2,
        positive: 2,
        abstain: 0,
        na: 0
      },
      meta: {
        probe_attempts: 1,
        probe_successes: 0,
        ml_inject_attempts: 4,
        ml_inject_successes: 1, // Inconsistent: 1 vs 2
        counters_consistent: false,
        processing_time: "0.8s"
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={assessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_only"
      />
    );

    // Check that counters inconsistent warning is shown
    expect(screen.getByText('⚠️ Counters Inconsistent')).toBeInTheDocument();
    expect(screen.getByText('Event counters don\'t match table rows. Check server logs for details.')).toBeInTheDocument();
  });

  test('Shows totals mismatch warning when summary total != results count + NA', () => {
    const assessmentResult = {
      results: [
        { decision: "positive", provenance: "Inject", rank_source: "ml", family: "xss" },
        { decision: "abstain", provenance: "Inject", rank_source: "ctx_pool", family: "xss" }
      ],
      summary: {
        confirmed_probe: 0,
        confirmed_ml_inject: 1,
        positive: 1,
        abstain: 1,
        na: 3,
        total: 7 // This creates a mismatch: summary total is 7, but results.length (2) + na (3) = 5
      },
      meta: {
        probe_attempts: 0,
        probe_successes: 0,
        ml_inject_attempts: 2,
        ml_inject_successes: 1,
        counters_consistent: true,
        processing_time: "0.5s"
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={assessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
        strategy="ml_only"
      />
    );

    // Check that totals mismatch warning is shown
    expect(screen.getByText('⚠️ Totals Mismatch')).toBeInTheDocument();
    expect(screen.getByText(/Summary total \(7\) ≠ Results count \(2\) \+ NA count \(3\)/)).toBeInTheDocument();
  });
});
