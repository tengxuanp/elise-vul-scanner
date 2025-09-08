import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

// Mock the counts reducer logic from assess page
const calculateCounts = (results) => {
  const totalResults = results.length;
  const positiveResults = results.filter(r => r.decision === "positive");
  const suspectedResults = results.filter(r => r.decision === "suspected");
  const abstainResults = results.filter(r => r.decision === "abstain");
  const naResults = results.filter(r => r.decision === "not_applicable");
  const errorResults = results.filter(r => r.decision === "error");
  
  const categorySum = positiveResults.length + suspectedResults.length + abstainResults.length + naResults.length + errorResults.length;
  const countsConsistent = totalResults === categorySum;
  
  return {
    total: totalResults,
    positive: positiveResults.length,
    suspected: suspectedResults.length,
    abstain: abstainResults.length,
    na: naResults.length,
    error: errorResults.length,
    categorySum,
    countsConsistent
  };
};

describe('Counts Reducer', () => {
  it('calculates correct counts for mixed results', () => {
    const results = [
      { decision: "positive", family: "xss" },
      { decision: "positive", family: "sqli" },
      { decision: "suspected", family: "xss" },
      { decision: "abstain", family: "xss" },
      { decision: "not_applicable", family: "xss" },
      { decision: "error", family: "xss" }
    ];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(6);
    expect(counts.positive).toBe(2);
    expect(counts.suspected).toBe(1);
    expect(counts.abstain).toBe(1);
    expect(counts.na).toBe(1);
    expect(counts.error).toBe(1);
    expect(counts.categorySum).toBe(6);
    expect(counts.countsConsistent).toBe(true);
  });

  it('handles empty results array', () => {
    const results = [];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(0);
    expect(counts.positive).toBe(0);
    expect(counts.suspected).toBe(0);
    expect(counts.abstain).toBe(0);
    expect(counts.na).toBe(0);
    expect(counts.error).toBe(0);
    expect(counts.categorySum).toBe(0);
    expect(counts.countsConsistent).toBe(true);
  });

  it('handles only positive results', () => {
    const results = [
      { decision: "positive", family: "xss" },
      { decision: "positive", family: "sqli" },
      { decision: "positive", family: "redirect" }
    ];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(3);
    expect(counts.positive).toBe(3);
    expect(counts.suspected).toBe(0);
    expect(counts.abstain).toBe(0);
    expect(counts.na).toBe(0);
    expect(counts.error).toBe(0);
    expect(counts.categorySum).toBe(3);
    expect(counts.countsConsistent).toBe(true);
  });

  it('handles only NA results', () => {
    const results = [
      { decision: "not_applicable", family: "xss" },
      { decision: "not_applicable", family: "sqli" }
    ];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(2);
    expect(counts.positive).toBe(0);
    expect(counts.suspected).toBe(0);
    expect(counts.abstain).toBe(0);
    expect(counts.na).toBe(2);
    expect(counts.error).toBe(0);
    expect(counts.categorySum).toBe(2);
    expect(counts.countsConsistent).toBe(true);
  });

  it('detects counts inconsistency (hypothetical edge case)', () => {
    // This test simulates what would happen if there was a bug
    // where results had unexpected decision values
    const results = [
      { decision: "positive", family: "xss" },
      { decision: "suspected", family: "xss" },
      { decision: "unknown_decision", family: "xss" } // This wouldn't be counted in categories
    ];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(3);
    expect(counts.positive).toBe(1);
    expect(counts.suspected).toBe(1);
    expect(counts.abstain).toBe(0);
    expect(counts.na).toBe(0);
    expect(counts.error).toBe(0);
    expect(counts.categorySum).toBe(2); // Only known decisions counted
    expect(counts.countsConsistent).toBe(false);
  });

  it('handles mixed decision types correctly', () => {
    const results = [
      { decision: "positive", family: "xss" },
      { decision: "suspected", family: "sqli" },
      { decision: "abstain", family: "xss" },
      { decision: "not_applicable", family: "redirect" },
      { decision: "error", family: "xss" },
      { decision: "positive", family: "sqli" },
      { decision: "suspected", family: "xss" }
    ];
    
    const counts = calculateCounts(results);
    
    expect(counts.total).toBe(7);
    expect(counts.positive).toBe(2);
    expect(counts.suspected).toBe(2);
    expect(counts.abstain).toBe(1);
    expect(counts.na).toBe(1);
    expect(counts.error).toBe(1);
    expect(counts.categorySum).toBe(7);
    expect(counts.countsConsistent).toBe(true);
  });
});
