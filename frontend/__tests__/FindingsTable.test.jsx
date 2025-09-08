/**
 * @jest-environment jsdom
 */
import { render, screen, fireEvent } from '@testing-library/react';
import FindingsTable from '../src/app/components/FindingsTable';

// Mock the lucide-react icons
jest.mock('lucide-react', () => ({
  TriangleAlert: () => <div data-testid="triangle-alert" />,
  ShieldCheck: () => <div data-testid="shield-check" />,
  Database: () => <div data-testid="database" />,
  Link: () => <div data-testid="link" />,
  ChevronDown: () => <div data-testid="chevron-down" />,
  ChevronRight: () => <div data-testid="chevron-right" />,
}));

const mockResults = [
  {
    evidence_id: "test-1",
    family: "xss",
    url: "http://test.com/page1",
    method: "GET",
    param_in: "query",
    param: "search",
    decision: "positive",
    why: ["probe_proof"],
    cvss: { base: 6.1 },
    rank_source: "probe_only",
    ml_proba: null,
    xss_context: "html_body",
    xss_escaping: "raw"
  },
  {
    evidence_id: "test-2", 
    family: "sqli",
    url: "http://test.com/login",
    method: "POST",
    param_in: "form",
    param: "username",
    decision: "positive",
    why: ["probe_proof"],
    cvss: { base: 7.5 },
    rank_source: "ml",
    ml_proba: 0.85,
    dialect: "mysql",
    dialect_confident: true
  },
  {
    evidence_id: "test-3",
    family: "xss",
    url: "http://test.com/comment",
    method: "POST", 
    param_in: "form",
    param: "content",
    decision: "clean",
    why: ["no_parameters_detected"],
    cvss: null,
    rank_source: "defaults",
    ml_proba: null
  }
];

describe('FindingsTable', () => {
  const mockOnView = jest.fn();

  beforeEach(() => {
    mockOnView.mockClear();
  });

  it('renders no results message when empty', () => {
    render(<FindingsTable results={[]} onView={mockOnView} />);
    expect(screen.getByText('No results yet.')).toBeInTheDocument();
  });

  it('renders results grouped by decision', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show sections for positive and clean
    expect(screen.getByText('Positive (2)')).toBeInTheDocument();
    expect(screen.getByText('Clean (1)')).toBeInTheDocument();
  });

  it('shows XSS context/escaping chips for XSS findings', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show XSS context chip
    expect(screen.getByTitle('XSS Context: html_body, Escaping: raw')).toBeInTheDocument();
    expect(screen.getByText('html/raw')).toBeInTheDocument();
  });

  it('shows SQLi dialect chip for SQLi findings', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show SQLi dialect chip
    expect(screen.getByTitle('Detected Dialect: mysql (confident)')).toBeInTheDocument();
    expect(screen.getByText('MySQL')).toBeInTheDocument();
  });

  it('shows ML chip for ML-ranked findings', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show ML chip with probability
    expect(screen.getByTitle('ML prioritized payload; decision from probe proof.')).toBeInTheDocument();
    expect(screen.getByText('ML p=0.85')).toBeInTheDocument();
  });

  it('shows rank source badges', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show different rank source badges
    expect(screen.getByText('probe_only')).toBeInTheDocument();
    expect(screen.getByText('ml')).toBeInTheDocument();
    expect(screen.getByText('defaults')).toBeInTheDocument();
  });

  it('calls onView when Evidence button is clicked', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    const evidenceButtons = screen.getAllByText('Evidence');
    fireEvent.click(evidenceButtons[0]);
    
    expect(mockOnView).toHaveBeenCalledWith('test-1');
  });

  it('toggles section expansion when clicked', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    const positiveSection = screen.getByText('Positive (2)');
    fireEvent.click(positiveSection);
    
    // Section should be collapsed (no table visible)
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shows correct decision badges', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show positive and clean badges
    expect(screen.getByText('positive')).toBeInTheDocument();
    expect(screen.getByText('clean')).toBeInTheDocument();
  });

  it('displays CVSS scores correctly', () => {
    render(<FindingsTable results={mockResults} onView={mockOnView} />);
    
    // Should show CVSS scores for positive findings
    expect(screen.getByText('6.1')).toBeInTheDocument();
    expect(screen.getByText('7.5')).toBeInTheDocument();
    
    // Should show — for clean findings
    expect(screen.getAllByText('—')).toHaveLength(2); // ML proba and CVSS for clean
  });

  it('handles missing optional fields gracefully', () => {
    const minimalResult = {
      evidence_id: "test-minimal",
      family: "xss",
      url: "http://test.com",
      method: "GET",
      param_in: "query", 
      param: "test",
      decision: "positive",
      why: ["probe_proof"],
      cvss: { base: 5.0 },
      rank_source: "probe_only"
    };

    render(<FindingsTable results={[minimalResult]} onView={mockOnView} />);
    
    // Should render without errors
    expect(screen.getByText('positive')).toBeInTheDocument();
    expect(screen.getByText('5.0')).toBeInTheDocument();
  });
});
