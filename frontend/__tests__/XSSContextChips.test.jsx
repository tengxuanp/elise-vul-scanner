import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

// Import the component (we'll need to extract it from FindingsTable)
import FindingsTable from '../src/app/components/FindingsTable';

describe('XSSContextChips', () => {
  // Helper function to render just the XSSContextChips part
  const renderXSSContextChips = (props) => {
    const mockResult = {
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
      ...props
    };

    const { container } = render(
      <FindingsTable results={[mockResult]} onView={() => {}} />
    );
    
    return container;
  };

  it('renders context/escaping chips for XSS findings', () => {
    const container = renderXSSContextChips({
      xss_context: 'js_string',
      xss_escaping: 'raw'
    });

    // Check for the context/escaping chip
    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).toBeInTheDocument();
    expect(contextChip).toHaveTextContent('js/raw');
    expect(contextChip).toHaveAttribute('title', 'XSS Context: js_string, Escaping: raw');
  });

  it('shows ML confidence badge when ML was used', () => {
    const container = renderXSSContextChips({
      xss_context: 'html_body',
      xss_escaping: 'html',
      xss_context_ml: {
        pred: 'html_body',
        proba: 0.85
      },
      xss_escaping_ml: {
        pred: 'html',
        proba: 0.90
      }
    });

    // Check for the context/escaping chip
    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).toBeInTheDocument();
    expect(contextChip).toHaveTextContent('html/html');

    // Check for ML confidence badge
    const mlBadge = container.querySelector('.bg-purple-100');
    expect(mlBadge).toBeInTheDocument();
    expect(mlBadge).toHaveTextContent('ML 0.90'); // Should show max confidence
    expect(mlBadge).toHaveAttribute('title', 'ML-assisted classification');
  });

  it('shows ML confidence badge with context ML only', () => {
    const container = renderXSSContextChips({
      xss_context: 'attr',
      xss_escaping: 'raw',
      xss_context_ml: {
        pred: 'attr',
        proba: 0.75
      }
      // No escaping ML
    });

    // Check for ML confidence badge
    const mlBadge = container.querySelector('.bg-purple-100');
    expect(mlBadge).toBeInTheDocument();
    expect(mlBadge).toHaveTextContent('ML 0.75');
  });

  it('shows ML confidence badge with escaping ML only', () => {
    const container = renderXSSContextChips({
      xss_context: 'css',
      xss_escaping: 'url',
      xss_escaping_ml: {
        pred: 'url',
        proba: 0.82
      }
      // No context ML
    });

    // Check for ML confidence badge
    const mlBadge = container.querySelector('.bg-purple-100');
    expect(mlBadge).toBeInTheDocument();
    expect(mlBadge).toHaveTextContent('ML 0.82');
  });

  it('does not show ML badge when no ML was used', () => {
    const container = renderXSSContextChips({
      xss_context: 'url',
      xss_escaping: 'js'
      // No ML fields
    });

    // Check for context/escaping chip
    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).toBeInTheDocument();
    expect(contextChip).toHaveTextContent('url/js');

    // Should not have ML badge
    const mlBadge = container.querySelector('.bg-purple-100');
    expect(mlBadge).not.toBeInTheDocument();
  });

  it('handles unknown context and escaping', () => {
    const container = renderXSSContextChips({
      xss_context: 'unknown',
      xss_escaping: 'unknown'
    });

    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).toBeInTheDocument();
    expect(contextChip).toHaveTextContent('?/?');
  });

  it('does not render for non-XSS findings', () => {
    const container = renderXSSContextChips({
      family: 'sqli', // Not XSS
      xss_context: 'js_string',
      xss_escaping: 'raw'
    });

    // Should not have XSS context chip
    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).not.toBeInTheDocument();
  });

  it('does not render when context or escaping is missing', () => {
    const container = renderXSSContextChips({
      xss_context: 'js_string'
      // Missing xss_escaping
    });

    // Should not have XSS context chip
    const contextChip = container.querySelector('.bg-orange-100');
    expect(contextChip).not.toBeInTheDocument();
  });

  it('maps context and escaping values correctly', () => {
    const testCases = [
      { context: 'html_body', escaping: 'raw', expected: 'html/raw' },
      { context: 'attr', escaping: 'html', expected: 'attr/html' },
      { context: 'js_string', escaping: 'js', expected: 'js/js' },
      { context: 'url', escaping: 'url', expected: 'url/url' },
      { context: 'css', escaping: 'raw', expected: 'css/raw' }
    ];

    testCases.forEach(({ context, escaping, expected }) => {
      const container = renderXSSContextChips({
        xss_context: context,
        xss_escaping: escaping
      });

      const contextChip = container.querySelector('.bg-orange-100');
      expect(contextChip).toHaveTextContent(expected);
    });
  });
});
