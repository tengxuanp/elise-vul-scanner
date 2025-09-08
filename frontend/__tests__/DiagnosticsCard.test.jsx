import React from 'react';
import { render, screen, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import DiagnosticsCard from '../src/app/components/DiagnosticsCard';

describe('DiagnosticsCard', () => {
  const mockHealthzData = {
    ok: true,
    use_ml: true,
    ml_active: true,
    require_ranker: false,
    models_available: {
      xss: { has_model: true, has_defaults: true },
      sqli: { has_model: true, has_defaults: true }
    },
    thresholds: {
      sqli_tau: 0.5,
      xss_tau: 0.75,
      redirect_tau: 0.6
    },
    using_defaults: false,
    ml_status: 'models_available',
    playwright_ok: true,
    crawler_import_ok: true,
    failed_checks: []
  };

  it('renders with all status information', () => {
    render(<DiagnosticsCard healthz={mockHealthzData} />);

    expect(screen.getByText('Diagnostics')).toBeInTheDocument();
    expect(screen.getByText('ML Mode:')).toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('shows Playwright and Crawler import status when expanded', () => {
    render(<DiagnosticsCard healthz={mockHealthzData} />);

    // Click expand button
    const expandButton = screen.getByText('Expand');
    act(() => {
      expandButton.click();
    });

    // Check that the new status fields are displayed
    expect(screen.getByText('Playwright:')).toBeInTheDocument();
    expect(screen.getByText('Crawler import:')).toBeInTheDocument();
    
    // Check for OK status (there should be multiple OK texts, so use getAllByText)
    const okElements = screen.getAllByText('OK');
    expect(okElements.length).toBeGreaterThan(0);
  });

  it('shows Fail status when imports fail', () => {
    const failedHealthzData = {
      ...mockHealthzData,
      playwright_ok: false,
      crawler_import_ok: false,
      failed_checks: ['Playwright: Fail', 'Crawler import: Fail']
    };

    render(<DiagnosticsCard healthz={failedHealthzData} />);

    // Click expand button
    const expandButton = screen.getByText('Expand');
    act(() => {
      expandButton.click();
    });

    // Check that the failed status is displayed
    expect(screen.getByText('Playwright:')).toBeInTheDocument();
    expect(screen.getByText('Crawler import:')).toBeInTheDocument();
    
    // Should show Fail status (there should be multiple "Fail" texts)
    const failElements = screen.getAllByText('Fail');
    expect(failElements.length).toBeGreaterThan(0);
  });

  it('handles missing healthz data', () => {
    render(<DiagnosticsCard healthz={null} />);

    expect(screen.getByText('Diagnostics')).toBeInTheDocument();
    expect(screen.getByText('No diagnostic data available')).toBeInTheDocument();
  });
});
