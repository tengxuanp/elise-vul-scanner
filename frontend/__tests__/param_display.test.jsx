import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import FindingsTable from '../src/app/components/FindingsTable';

describe('Param Display', () => {
  const renderFindingsTable = (results) => {
    return render(
      <FindingsTable results={results} onView={() => {}} />
    );
  };

  it('displays param_in:param when both are present', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test',
        param_in: 'query',
        param: 'q',
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-123'
      }
    ];

    renderFindingsTable(results);

    // Check that param is displayed correctly
    expect(screen.getByText('query:q')).toBeInTheDocument();
  });

  it('displays header:location for redirect family when param info missing', () => {
    const results = [
      {
        family: 'redirect',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test',
        // No param_in or param
        why: ['redirect_location_reflects'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 4.3 },
        evidence_id: 'test-evidence-456'
      }
    ];

    renderFindingsTable(results);

    // Check that redirect fallback is displayed
    expect(screen.getByText('header:location')).toBeInTheDocument();
  });

  it('displays none:none (greyed) for other families when param info missing', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test',
        // No param_in or param
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-789'
      }
    ];

    const { container } = renderFindingsTable(results);

    // Check that none:none is displayed and greyed
    const paramCells = container.querySelectorAll('.text-gray-500');
    const paramCell = Array.from(paramCells).find(cell => cell.textContent === 'none:none');
    expect(paramCell).toBeInTheDocument();
    expect(paramCell).toHaveTextContent('none:none');
  });

  it('displays form:content for form parameters', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'POST',
        url: 'http://example.com/test',
        param_in: 'form',
        param: 'content',
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-form'
      }
    ];

    renderFindingsTable(results);

    // Check that form param is displayed correctly
    expect(screen.getByText('form:content')).toBeInTheDocument();
  });

  it('displays json:data for JSON parameters', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'POST',
        url: 'http://example.com/test',
        param_in: 'json',
        param: 'data',
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-json'
      }
    ];

    renderFindingsTable(results);

    // Check that JSON param is displayed correctly
    expect(screen.getByText('json:data')).toBeInTheDocument();
  });

  it('displays unknown:<reflected> for unknown param_in', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test',
        param_in: 'unknown',
        param: '<reflected>',
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-unknown'
      }
    ];

    renderFindingsTable(results);

    // Check that unknown param is displayed correctly
    expect(screen.getByText('unknown:<reflected>')).toBeInTheDocument();
  });

  it('handles mixed results with different param display patterns', () => {
    const results = [
      {
        family: 'xss',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test1',
        param_in: 'query',
        param: 'q',
        why: ['xss_reflection'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 6.1 },
        evidence_id: 'test-evidence-1'
      },
      {
        family: 'redirect',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test2',
        // No param info
        why: ['redirect_location_reflects'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 4.3 },
        evidence_id: 'test-evidence-2'
      },
      {
        family: 'sqli',
        decision: 'positive',
        method: 'GET',
        url: 'http://example.com/test3',
        // No param info
        why: ['sql_boolean_delta'],
        rank_source: 'probe_only',
        ml_proba: null,
        cvss: { base: 7.5 },
        evidence_id: 'test-evidence-3'
      }
    ];

    const { container } = renderFindingsTable(results);

    // Check all three patterns are displayed
    expect(screen.getByText('query:q')).toBeInTheDocument();
    expect(screen.getByText('header:location')).toBeInTheDocument();
    
    const greyedCells = container.querySelectorAll('.text-gray-500');
    expect(greyedCells.length).toBeGreaterThan(0);
    expect(Array.from(greyedCells).some(cell => cell.textContent === 'none:none')).toBe(true);
  });
});
