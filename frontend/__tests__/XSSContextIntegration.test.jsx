import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import FindingsTable from '../src/app/components/FindingsTable';
import SummaryPanel from '../src/app/components/SummaryPanel';

describe('XSS Context Integration', () => {
  describe('FindingsTable XSS Context Chips', () => {
    const renderFindingsTable = (results) => {
      return render(
        <FindingsTable results={results} onView={() => {}} />
      );
    };

    it('renders XSS context chips for XSS findings with rule-based context', () => {
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
          xss_context: 'js_string',
          xss_escaping: 'raw',
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);

      // Check for the context/escaping chip
      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).toBeInTheDocument();
      expect(contextChip).toHaveTextContent('js/raw');
      expect(contextChip).toHaveAttribute('title', 'XSS Context: js_string, Escaping: raw');

      // Should not have ML badge for rule-based context
      const mlBadge = container.querySelector('.bg-purple-100');
      expect(mlBadge).not.toBeInTheDocument();
    });

    it('renders XSS context chips with ML badge for ML-based context', () => {
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
          xss_escaping: 'html',
          xss_context_source: 'ml',
          xss_context_ml_proba: 0.85
        }
      ];

      const { container } = renderFindingsTable(results);

      // Check for the context/escaping chip
      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).toBeInTheDocument();
      expect(contextChip).toHaveTextContent('html/html');

      // Check for ML confidence badge
      const mlBadge = container.querySelector('.bg-purple-100');
      expect(mlBadge).toBeInTheDocument();
      expect(mlBadge).toHaveTextContent('ML 0.85');
      expect(mlBadge).toHaveAttribute('title', 'ML-assisted classification');
    });

    it('handles different XSS context types correctly', () => {
      const testCases = [
        { context: 'html_body', escaping: 'raw', expected: 'html/raw' },
        { context: 'attr', escaping: 'html', expected: 'attr/html' },
        { context: 'js_string', escaping: 'js', expected: 'js/js' },
        { context: 'url', escaping: 'url', expected: 'url/url' },
        { context: 'css', escaping: 'raw', expected: 'css/raw' },
        { context: 'unknown', escaping: 'unknown', expected: '?/?' }
      ];

      testCases.forEach(({ context, escaping, expected }) => {
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
            xss_context: context,
            xss_escaping: escaping,
            xss_context_source: 'rule',
            xss_context_ml_proba: null
          }
        ];

        const { container } = renderFindingsTable(results);
        const contextChip = container.querySelector('.bg-orange-100');
        expect(contextChip).toHaveTextContent(expected);
      });
    });

    it('does not render XSS context chips for non-XSS findings', () => {
      const results = [
        {
          family: 'sqli',
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
          xss_context: 'js_string',
          xss_escaping: 'raw',
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);
      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).not.toBeInTheDocument();
    });

    it('does not render XSS context chips when context or escaping is missing', () => {
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
          xss_context: 'js_string',
          // Missing xss_escaping
          xss_context_source: 'rule',
          xss_context_ml_proba: null
        }
      ];

      const { container } = renderFindingsTable(results);
      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).not.toBeInTheDocument();
    });
  });

  describe('SummaryPanel XSS Context Statistics', () => {
    const renderSummaryPanel = (assessmentResult, mlMode = 'Calibrated models', jobId = 'test-job') => {
      return render(
        <SummaryPanel 
          assessmentResult={assessmentResult}
          mlMode={mlMode}
          jobId={jobId}
        />
      );
    };

    it('renders XSS context statistics when XSS reflections are present', () => {
      const assessmentResult = {
        summary: {
          total: 3,
          positive: 2,
          suspected: 0,
          abstain: 0,
          na: 1
        },
        meta: {
          endpoints_supplied: 2,
          targets_enumerated: 2,
          processing_ms: 1500,
          processing_time: '1.5s',
          probe_attempts: 2,
          probe_successes: 2,
          ml_inject_attempts: 0,
          ml_inject_successes: 0,
          xss_reflections_total: 2,
          xss_rule_high_conf: 1,
          xss_ml_invoked: 1,
          xss_final_from_ml: 1,
          xss_context_dist: {
            'js_string': 1,
            'html_body': 1
          }
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Check for XSS Context Analysis section
      expect(screen.getByText('XSS Context Analysis')).toBeInTheDocument();
      
      // Check for XSS reflection counters
      expect(screen.getByText('XSS reflections')).toBeInTheDocument();
      // Check for the specific XSS reflections count by looking in the parent container
      const xssReflectionsContainer = screen.getByText('XSS reflections').parentElement;
      expect(xssReflectionsContainer).toHaveTextContent('2');
      
      expect(screen.getByText('Rule high-conf')).toBeInTheDocument();
      expect(screen.getByText('ML invoked')).toBeInTheDocument();
      expect(screen.getByText('Final from ML')).toBeInTheDocument();
      
      // Check for context distribution
      expect(screen.getByText('Context Distribution')).toBeInTheDocument();
      expect(screen.getByText('js_string: 1')).toBeInTheDocument();
      expect(screen.getByText('html_body: 1')).toBeInTheDocument();
    });

    it('does not render XSS context statistics when no XSS reflections', () => {
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

    it('handles missing XSS context counters gracefully', () => {
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
          ml_inject_successes: 0
          // Missing XSS context counters
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Should not render XSS Context Analysis section
      expect(screen.queryByText('XSS Context Analysis')).not.toBeInTheDocument();
    });

    it('renders context distribution chips correctly', () => {
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
          probe_successes: 3,
          ml_inject_attempts: 0,
          ml_inject_successes: 0,
          xss_reflections_total: 3,
          xss_rule_high_conf: 2,
          xss_ml_invoked: 1,
          xss_final_from_ml: 1,
          xss_context_dist: {
            'js_string': 2,
            'attr': 1,
            'html_body': 0
          }
        },
        results: []
      };

      const { container } = renderSummaryPanel(assessmentResult);

      // Check for context distribution chips
      expect(screen.getByText('js_string: 2')).toBeInTheDocument();
      expect(screen.getByText('attr: 1')).toBeInTheDocument();
      
      // Check tooltips
      const jsStringChip = screen.getByTitle('js_string: 2 reflections');
      expect(jsStringChip).toBeInTheDocument();
      
      const attrChip = screen.getByTitle('attr: 1 reflections');
      expect(attrChip).toBeInTheDocument();
    });
  });
});
