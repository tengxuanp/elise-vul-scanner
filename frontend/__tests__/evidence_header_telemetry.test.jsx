/**
 * Test evidence header telemetry display.
 * Modal displays Attempt/Top-K/Rank from evidence telemetry.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import EvidenceModal from '../src/app/components/EvidenceModal';

// Mock the API call
jest.mock('../src/lib/api', () => ({
  API_BASE: 'http://localhost:8000/api'
}));

// Mock fetch
global.fetch = jest.fn();

describe('EvidenceModal - Header Telemetry', () => {
  beforeEach(() => {
    fetch.mockClear();
  });

  test('Displays telemetry from evidence.telemetry field', async () => {
    const mockEvidence = {
      family: "xss",
      url: "http://example.com/search",
      method: "GET",
      telemetry: {
        attempt_idx: 2,
        top_k_used: 5,
        rank_source: "ctx_pool"
      },
      ranking_topk: [
        { payload_id: "<script>alert(1)</script>", score: 0.8, family: "xss" },
        { payload_id: "<img src=x onerror=alert(1)>", score: 0.7, family: "xss" }
      ],
      attempts_timeline: [
        {
          attempt_idx: 2,
          payload_id: "<script>alert(1)</script>",
          request: { method: "GET", path: "/search", param_in: "query", param: "q" },
          response: { status: 200, latency_ms: 150 },
          hit: true,
          why: ["signal:reflection+payload"],
          rank_source: "ctx_pool"
        }
      ]
    };

    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockEvidence,
    });

    render(
      <EvidenceModal 
        open={true}
        onClose={() => {}}
        evidenceId="test-evidence-123"
        jobId="test-job-123"
        meta={{ ml_inject_attempts: 5 }}
      />
    );

    // Wait for the evidence to load
    await screen.findByText('Attempt: 2');
    
    // Check that telemetry is displayed correctly
    expect(screen.getByText('Attempt: 2')).toBeInTheDocument();
    expect(screen.getByText('Top-K: 5')).toBeInTheDocument();
    expect(screen.getByText('Rank: ctx_pool')).toBeInTheDocument();
  });

  test('Falls back to legacy fields when telemetry is not available', async () => {
    const mockEvidence = {
      family: "xss",
      url: "http://example.com/search",
      method: "GET",
      // No telemetry field
      attempt_idx: 3,
      top_k_used: 3,
      rank_source: "ml",
      ranking_topk: [
        { payload_id: "<script>alert(1)</script>", score: 0.8, family: "xss" }
      ]
    };

    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockEvidence,
    });

    render(
      <EvidenceModal 
        open={true}
        onClose={() => {}}
        evidenceId="test-evidence-123"
        jobId="test-job-123"
        meta={{ ml_inject_attempts: 3 }}
      />
    );

    // Wait for the evidence to load
    await screen.findByText('Attempt: 3');
    
    // Check that legacy fields are used as fallback
    expect(screen.getByText('Attempt: 3')).toBeInTheDocument();
    expect(screen.getByText('Top-K: 3')).toBeInTheDocument();
    expect(screen.getByText('Rank: ml')).toBeInTheDocument();
  });

  test('Shows default values when no telemetry or legacy fields available', async () => {
    const mockEvidence = {
      family: "xss",
      url: "http://example.com/search",
      method: "GET",
      // No telemetry or legacy fields
      ranking_topk: []
    };

    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockEvidence,
    });

    render(
      <EvidenceModal 
        open={true}
        onClose={() => {}}
        evidenceId="test-evidence-123"
        jobId="test-job-123"
        meta={{ ml_inject_attempts: 0 }}
      />
    );

    // Wait for the evidence to load
    await screen.findByText('Attempt: 0');
    
    // Check that default values are shown
    expect(screen.getByText('Attempt: 0')).toBeInTheDocument();
    expect(screen.getByText('Top-K: 0')).toBeInTheDocument();
    expect(screen.getByText('Rank: —')).toBeInTheDocument();
  });

  test('Shows probe telemetry correctly', async () => {
    const mockEvidence = {
      family: "sqli",
      url: "http://example.com/login",
      method: "POST",
      telemetry: {
        attempt_idx: 0,
        top_k_used: 0,
        rank_source: "probe_only"
      },
      ranking_topk: [],
      attempts_timeline: []
    };

    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockEvidence,
    });

    render(
      <EvidenceModal 
        open={true}
        onClose={() => {}}
        evidenceId="test-evidence-123"
        jobId="test-job-123"
        meta={{ ml_inject_attempts: 0 }}
      />
    );

    // Wait for the evidence to load
    await screen.findByText('Attempt: 0');
    
    // Check that probe telemetry is displayed correctly
    expect(screen.getByText('Attempt: 0')).toBeInTheDocument();
    expect(screen.getByText('Top-K: 0')).toBeInTheDocument();
    expect(screen.getByText('Rank: probe_only')).toBeInTheDocument();
  });
});
