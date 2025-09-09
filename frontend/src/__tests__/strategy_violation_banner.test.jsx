/**
 * @jest-environment jsdom
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import SummaryPanel from '../app/components/SummaryPanel';

describe('Strategy Violation Banner', () => {
  const mockAssessmentResult = {
    summary: {
      total: 5,
      positive: 2,
      suspected: 1,
      abstain: 1,
      na: 1
    },
    meta: {
      strategy: "ml_only",
      probe_attempts: 0,
      ml_inject_attempts: 3,
      violations: []
    },
    results: []
  };

  it('does not show violation banner when no violations', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.queryByText('⚠️ Strategy Violation')).not.toBeInTheDocument();
  });

  it('shows violation banner when ML-only has probe attempts', () => {
    const resultWithViolation = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        probe_attempts: 2
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithViolation}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('⚠️ Strategy Violation')).toBeInTheDocument();
    expect(screen.getByText('Probes ran under ML-only strategy')).toBeInTheDocument();
  });

  it('shows violation banner when ML-only has confirmed probe results', () => {
    const resultWithViolation = {
      ...mockAssessmentResult,
      summary: {
        ...mockAssessmentResult.summary,
        confirmed_probe: 1
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithViolation}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('⚠️ Strategy Violation')).toBeInTheDocument();
    expect(screen.getByText('Probes ran under ML-only strategy')).toBeInTheDocument();
  });

  it('shows violation banner with specific violations list', () => {
    const resultWithViolations = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        violations: [
          "strategy_violation:xss_probe_ran",
          "strategy_violation:sqli_probe_ran"
        ]
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithViolations}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('⚠️ Strategy Violation')).toBeInTheDocument();
    expect(screen.getByText('Violations detected:')).toBeInTheDocument();
    expect(screen.getByText('strategy_violation:xss_probe_ran')).toBeInTheDocument();
    expect(screen.getByText('strategy_violation:sqli_probe_ran')).toBeInTheDocument();
  });

  it('does not show violation banner for auto strategy with probes', () => {
    const autoResult = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        strategy: "auto",
        probe_attempts: 3
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={autoResult}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="auto"
      />
    );
    
    expect(screen.queryByText('⚠️ Strategy Violation')).not.toBeInTheDocument();
  });

  it('does not show violation banner for probe_only strategy with probes', () => {
    const probeOnlyResult = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        strategy: "probe_only",
        probe_attempts: 3
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={probeOnlyResult}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="probe_only"
      />
    );
    
    expect(screen.queryByText('⚠️ Strategy Violation')).not.toBeInTheDocument();
  });

  it('shows strategy badge correctly', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.getByText('Strategy: ML-only')).toBeInTheDocument();
  });

  it('handles missing meta data gracefully', () => {
    const resultWithoutMeta = {
      ...mockAssessmentResult,
      meta: {}
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithoutMeta}
        mlMode="Calibrated models"
        jobId="test-job"
        strategy="ml_only"
      />
    );
    
    expect(screen.queryByText('⚠️ Strategy Violation')).not.toBeInTheDocument();
  });
});
