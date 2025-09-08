import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SummaryPanel from '../src/app/components/SummaryPanel';

describe('SummaryPanel', () => {
  const mockAssessmentResult = {
    summary: {
      total: 5,
      positive: 2,
      suspected: 1,
      abstain: 1,
      na: 1
    },
    results: [
      {
        decision: "positive",
        rank_source: "probe_only"
      },
      {
        decision: "positive", 
        rank_source: "ml"
      },
      {
        decision: "suspected",
        rank_source: "probe_only"
      },
      {
        decision: "abstain",
        rank_source: "none"
      },
      {
        decision: "not_applicable",
        rank_source: "none"
      }
    ],
    meta: {
      endpoints_supplied: 3,
      targets_enumerated: 4,
      processing_ms: 1500,
      processing_time: "1.5s",
      probe_attempts: 2,
      probe_successes: 1,
      ml_inject_attempts: 3,
      ml_inject_successes: 1
    }
  };

  it('renders with server-reported counters', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
      />
    );

    // Check basic fields
    expect(screen.getByText('3')).toBeInTheDocument(); // endpoints_supplied
    expect(screen.getByText('4')).toBeInTheDocument(); // targets_enumerated
    
    // Check server-reported counters are displayed
    const probeSuccessElement = screen.getByText('Confirmed (Probe)').parentElement.querySelector('.font-semibold');
    const mlSuccessElement = screen.getByText('Confirmed (ML+Inject)').parentElement.querySelector('.font-semibold');
    expect(probeSuccessElement).toHaveTextContent('1');
    expect(mlSuccessElement).toHaveTextContent('1');
    
    // Check processing time
    expect(screen.getByText('1.5s')).toBeInTheDocument();
    
    // Check info icons for server-reported counters
    const infoIcons = screen.getAllByTitle('Server-reported counter');
    expect(infoIcons).toHaveLength(2); // One for probe, one for ML
  });

  it('falls back to computed counters when server counters missing', () => {
    const resultWithoutServerCounters = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        probe_successes: undefined,
        ml_inject_successes: undefined
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithoutServerCounters}
        mlMode="Calibrated models"
        jobId="test-job-123"
      />
    );

    // Should still show computed values
    const probeSuccessElement = screen.getByText('Confirmed (Probe)').parentElement.querySelector('.font-semibold');
    const mlSuccessElement = screen.getByText('Confirmed (ML+Inject)').parentElement.querySelector('.font-semibold');
    expect(probeSuccessElement).toHaveTextContent('1');
    expect(mlSuccessElement).toHaveTextContent('1');
    
    // Should not show info icons
    const infoIcons = screen.queryAllByTitle('Server-reported counter');
    expect(infoIcons).toHaveLength(0);
  });

  it('handles missing processing time gracefully', () => {
    const resultWithoutProcessingTime = {
      ...mockAssessmentResult,
      meta: {
        ...mockAssessmentResult.meta,
        processing_time: undefined,
        processing_ms: undefined
      }
    };

    render(
      <SummaryPanel 
        assessmentResult={resultWithoutProcessingTime}
        mlMode="Calibrated models"
        jobId="test-job-123"
      />
    );

    // Should show N/A for processing time
    expect(screen.getByText('N/A')).toBeInTheDocument();
  });

  it('shows correct ML mode badge', () => {
    render(
      <SummaryPanel 
        assessmentResult={mockAssessmentResult}
        mlMode="Calibrated models"
        jobId="test-job-123"
      />
    );

    expect(screen.getByText('ML: Calibrated models')).toBeInTheDocument();
  });

  it('handles empty assessment result', () => {
    render(
      <SummaryPanel 
        assessmentResult={null}
        mlMode="Off"
        jobId="test-job-123"
      />
    );

    // Should not render anything
    expect(screen.queryByText('Summary')).not.toBeInTheDocument();
  });
});
