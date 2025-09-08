import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import FindingsTable from '../src/app/components/FindingsTable';
import SummaryPanel from '../src/app/components/SummaryPanel';

describe('XSS Context Payload Selection', () => {
  describe('FindingsTable Context Pool Badge', () => {
    const renderFindingsTable = (results) => {
      return render(
        <FindingsTable results={results} onView={() => {}} />
      );
    };

    it('renders CTX badge for context pool rank source', () => {
      const results = [
        {
          family: 'xss',
          decision: 'positive',
          method: 'GET',
          url: 'http://example.com/test',
          param_in: 'query',
          param: 'q',
          why: ['ml_ranked'],
          rank_source: 'ctx_pool',
          ml_proba: null,
          cvss: { base: 6.1 },
          evidence_id: 'test-evidence-123',
          xss_context: 'attr',
          xss_escaping: 'html',
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);

      // Check for CTX badge
      const ctxBadge = container.querySelector('.bg-blue-100');
      expect(ctxBadge).toBeInTheDocument();
      expect(ctxBadge).toHaveTextContent('CTX');
      expect(ctxBadge).toHaveAttribute('title', 'Context-aware payload pool used for XSS');
    });

    it('renders ML badge for ml rank source', () => {
      const results = [
        {
          family: 'xss',
          decision: 'positive',
          method: 'GET',
          url: 'http://example.com/test',
          param_in: 'query',
          param: 'q',
          why: ['ml_ranked'],
          rank_source: 'ml',
          ml_proba: 0.85,
          cvss: { base: 6.1 },
          evidence_id: 'test-evidence-123',
          xss_context: 'js_string',
          xss_escaping: 'raw',
          xss_context_source: 'ml',
          xss_context_ml_proba: 0.85
        }
      ];

      const { container } = renderFindingsTable(results);

      // Check for ML badge - look for the specific MLChip component
      const mlBadges = container.querySelectorAll('.bg-purple-100');
      const mlBadge = Array.from(mlBadges).find(badge => badge.textContent.includes('ML p='));
      expect(mlBadge).toBeInTheDocument();
      expect(mlBadge).toHaveTextContent('ML p=0.85');
      expect(mlBadge).toHaveAttribute('title', 'ML prioritized payload; decision from probe proof.');
    });

    it('does not render badge for other rank sources', () => {
      const results = [
        {
          family: 'xss',
          decision: 'positive',
          method: 'GET',
          url: 'http://example.com/test',
          param_in: 'query',
          param: 'q',
          why: ['probe_proof'],
          rank_source: 'probe_only',
          ml_proba: null,
          cvss: { base: 6.1 },
          evidence_id: 'test-evidence-123',
          xss_context: 'html_body',
          xss_escaping: 'raw',
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);

      // Should not have CTX or ML badge from MLChip component
      const ctxBadges = container.querySelectorAll('.bg-blue-100');
      const mlBadges = container.querySelectorAll('.bg-purple-100');
      
      // Check that no CTX badge exists
      const ctxBadge = Array.from(ctxBadges).find(badge => badge.textContent.includes('CTX'));
      expect(ctxBadge).toBeUndefined();
      
      // Check that no ML badge with probability exists
      const mlBadge = Array.from(mlBadges).find(badge => badge.textContent.includes('ML p='));
      expect(mlBadge).toBeUndefined();
    });

    it('renders both CTX badge and XSS context chips together', () => {
      const results = [
        {
          family: 'xss',
          decision: 'positive',
          method: 'GET',
          url: 'http://example.com/test',
          param_in: 'query',
          param: 'q',
          why: ['ml_ranked'],
          rank_source: 'ctx_pool',
          ml_proba: null,
          cvss: { base: 6.1 },
          evidence_id: 'test-evidence-123',
          xss_context: 'attr',
          xss_escaping: 'html',
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);

      // Check for CTX badge - look for the specific MLChip component
      const ctxBadges = container.querySelectorAll('.bg-blue-100');
      const ctxBadge = Array.from(ctxBadges).find(badge => badge.textContent.includes('CTX'));
      expect(ctxBadge).toBeInTheDocument();
      expect(ctxBadge).toHaveTextContent('CTX');

      // Check for XSS context chips
      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).toBeInTheDocument();
      expect(contextChip).toHaveTextContent('attr/html');
    });
  });

  describe('SummaryPanel Context Pool Metrics', () => {
    const renderSummaryPanel = (assessmentResult, mlMode = 'Calibrated models', jobId = 'test-job') => {
      return render(
        <SummaryPanel 
          assessmentResult={assessmentResult}
          mlMode={mlMode}
          jobId={jobId}
        />
      );
    };

    it('renders context pool uplift metrics when available', () => {
      const assessmentResult = {
        summary: {
          total: 5,
          positive: 3,
          suspected: 0,
          abstain: 0,
          na: 2
        },
        meta: {
          endpoints_supplied: 3,
          targets_enumerated: 3,
          processing_ms: 2000,
          processing_time: '2.0s',
          probe_attempts: 3,
          probe_successes: 2,
          ml_inject_attempts: 1,
          ml_inject_successes: 1,
          xss_reflections_total: 3,
          xss_rule_high_conf: 2,
          xss_ml_invoked: 1,
          xss_final_from_ml: 1,
          xss_context_dist: {
            'attr': 2,
            'js_string': 1
          },
          xss_ctx_pool_used: 2,
          xss_first_hit_attempts_ctx: 3,
          xss_first_hit_attempts_baseline: 5,
          xss_first_hit_attempts_delta: 2
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Check for XSS Context Analysis section
      expect(screen.getByText('XSS Context Analysis')).toBeInTheDocument();
      
      // Check for context pool metrics
      expect(screen.getByText('Context pool used')).toBeInTheDocument();
      expect(screen.getByText('First-hit attempts (ctx)')).toBeInTheDocument();
      expect(screen.getByText('First-hit attempts (baseline)')).toBeInTheDocument();
      expect(screen.getByText('Attempts saved')).toBeInTheDocument();
      
      // Check for specific values
      const contextPoolContainer = screen.getByText('Context pool used').parentElement;
      expect(contextPoolContainer).toHaveTextContent('2');
      
      const ctxAttemptsContainer = screen.getByText('First-hit attempts (ctx)').parentElement;
      expect(ctxAttemptsContainer).toHaveTextContent('3');
      
      const baselineAttemptsContainer = screen.getByText('First-hit attempts (baseline)').parentElement;
      expect(baselineAttemptsContainer).toHaveTextContent('5');
      
      const savedAttemptsContainer = screen.getByText('Attempts saved').parentElement;
      expect(savedAttemptsContainer).toHaveTextContent('+2');
    });

    it('shows zero attempts saved when delta is zero or negative', () => {
      const assessmentResult = {
        summary: {
          total: 2,
          positive: 1,
          suspected: 0,
          abstain: 0,
          na: 1
        },
        meta: {
          endpoints_supplied: 2,
          targets_enumerated: 2,
          processing_ms: 1000,
          processing_time: '1.0s',
          probe_attempts: 2,
          probe_successes: 1,
          ml_inject_attempts: 0,
          ml_inject_successes: 0,
          xss_reflections_total: 1,
          xss_rule_high_conf: 1,
          xss_ml_invoked: 0,
          xss_final_from_ml: 0,
          xss_context_dist: {
            'html_body': 1
          },
          xss_ctx_pool_used: 1,
          xss_first_hit_attempts_ctx: 2,
          xss_first_hit_attempts_baseline: 1,
          xss_first_hit_attempts_delta: -1
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Check that attempts saved shows 0 for negative delta
      const savedAttemptsContainer = screen.getByText('Attempts saved').parentElement;
      expect(savedAttemptsContainer).toHaveTextContent('0');
    });

    it('handles missing context pool metrics gracefully', () => {
      const assessmentResult = {
        summary: {
          total: 1,
          positive: 1,
          suspected: 0,
          abstain: 0,
          na: 0
        },
        meta: {
          endpoints_supplied: 1,
          targets_enumerated: 1,
          processing_ms: 500,
          processing_time: '0.5s',
          probe_attempts: 1,
          probe_successes: 1,
          ml_inject_attempts: 0,
          ml_inject_successes: 0,
          xss_reflections_total: 1,
          xss_rule_high_conf: 1,
          xss_ml_invoked: 0,
          xss_final_from_ml: 0,
          xss_context_dist: {
            'html_body': 1
          }
          // Missing context pool metrics
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Should still render XSS Context Analysis section
      expect(screen.getByText('XSS Context Analysis')).toBeInTheDocument();
      
      // Should show 0 for missing metrics
      const contextPoolContainer = screen.getByText('Context pool used').parentElement;
      expect(contextPoolContainer).toHaveTextContent('0');
      
      const ctxAttemptsContainer = screen.getByText('First-hit attempts (ctx)').parentElement;
      expect(ctxAttemptsContainer).toHaveTextContent('0');
      
      const baselineAttemptsContainer = screen.getByText('First-hit attempts (baseline)').parentElement;
      expect(baselineAttemptsContainer).toHaveTextContent('0');
      
      const savedAttemptsContainer = screen.getByText('Attempts saved').parentElement;
      expect(savedAttemptsContainer).toHaveTextContent('0');
    });

    it('does not render context pool metrics when no XSS reflections', () => {
      const assessmentResult = {
        summary: {
          total: 2,
          positive: 1,
          suspected: 0,
          abstain: 0,
          na: 1
        },
        meta: {
          endpoints_supplied: 2,
          targets_enumerated: 2,
          processing_ms: 1000,
          processing_time: '1.0s',
          probe_attempts: 2,
          probe_successes: 1,
          ml_inject_attempts: 0,
          ml_inject_successes: 0,
          xss_reflections_total: 0,
          xss_rule_high_conf: 0,
          xss_ml_invoked: 0,
          xss_final_from_ml: 0,
          xss_context_dist: {}
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Should not render XSS Context Analysis section
      expect(screen.queryByText('XSS Context Analysis')).not.toBeInTheDocument();
    });
  });
});
