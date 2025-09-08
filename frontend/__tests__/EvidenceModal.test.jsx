/**
 * @jest-environment jsdom
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import EvidenceModal from '../src/app/components/EvidenceModal';

// Mock fetch
global.fetch = jest.fn();

// Mock the API_BASE
jest.mock('../src/lib/api', () => ({
  API_BASE: 'http://localhost:8000'
}));

const mockEvidence = {
  evidence_id: "test-evidence-123",
  family: "xss",
  url: "http://test.com/page",
  method: "GET",
  param_in: "query",
  param: "search",
  payload: "<script>alert('test')</script>",
  response_snippet_text: "&lt;script&gt;alert('test')&lt;/script&gt;",
  response_snippet_raw: "PHNjcmlwdD5hbGVydCgndGVzdCcpPC9zY3JpcHQ+",
  why: ["probe_proof"],
  cvss: { base: 6.1 },
  rank_source: "probe_only",
  ml_proba: null,
  timing_ms: 150
};

describe('EvidenceModal', () => {
  beforeEach(() => {
    fetch.mockClear();
  });

  it('renders nothing when closed', () => {
    render(
      <EvidenceModal 
        open={false} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows loading state when fetching evidence', async () => {
    fetch.mockImplementation(() => 
      new Promise(resolve => 
        setTimeout(() => resolve({
          ok: true,
          json: () => Promise.resolve(mockEvidence)
        }), 100)
      )
    );

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    expect(screen.getByText('Loading evidence...')).toBeInTheDocument();
  });

  it('displays evidence data when loaded', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('XSS Evidence')).toBeInTheDocument();
    });

    // Should show evidence details
    expect(screen.getByText('http://test.com/page')).toBeInTheDocument();
    expect(screen.getByText('GET')).toBeInTheDocument();
    expect(screen.getByText('query:search')).toBeInTheDocument();
    expect(screen.getByText('6.1')).toBeInTheDocument();
    expect(screen.getByText('150ms')).toBeInTheDocument();
  });

  it('renders response snippet as escaped text', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('Response Snippet')).toBeInTheDocument();
    });

    // Should show escaped HTML, not render it
    expect(screen.getByText(/&lt;script&gt;alert\('test'\)&lt;\/script&gt;/)).toBeInTheDocument();
  });

  it('handles download raw functionality', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    // Mock URL.createObjectURL and document.createElement
    const mockCreateObjectURL = jest.fn(() => 'blob:mock-url');
    const mockRevokeObjectURL = jest.fn();
    const mockClick = jest.fn();
    const mockAppendChild = jest.fn();
    const mockRemoveChild = jest.fn();

    global.URL.createObjectURL = mockCreateObjectURL;
    global.URL.revokeObjectURL = mockRevokeObjectURL;
    
    const mockAnchor = {
      href: '',
      download: '',
      click: mockClick
    };
    
    const mockDocument = {
      createElement: jest.fn(() => mockAnchor),
      body: {
        appendChild: mockAppendChild,
        removeChild: mockRemoveChild
      }
    };
    
    Object.defineProperty(global, 'document', {
      value: mockDocument,
      writable: true
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('Download raw')).toBeInTheDocument();
    });

    const downloadButton = screen.getByText('Download raw');
    fireEvent.click(downloadButton);

    expect(mockCreateObjectURL).toHaveBeenCalled();
    expect(mockClick).toHaveBeenCalled();
    expect(mockRevokeObjectURL).toHaveBeenCalled();
  });

  it('handles fetch errors gracefully', async () => {
    fetch.mockRejectedValueOnce(new Error('Network error'));

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('Failed to load evidence')).toBeInTheDocument();
    });
  });

  it('handles non-ok responses', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 404
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('Failed to load evidence')).toBeInTheDocument();
    });
  });

  it('calls onClose when close button is clicked', async () => {
    const mockOnClose = jest.fn();
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={mockOnClose} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByText('Close')).toBeInTheDocument();
    });

    const closeButton = screen.getByText('Close');
    fireEvent.click(closeButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('calls onClose when backdrop is clicked', async () => {
    const mockOnClose = jest.fn();
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={mockOnClose} 
        evidenceId="test-123" 
        jobId="test-job" 
      />
    );
    
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    const backdrop = screen.getByRole('dialog');
    fireEvent.click(backdrop);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('makes correct API call with jobId and evidenceId', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockEvidence)
    });

    render(
      <EvidenceModal 
        open={true} 
        onClose={jest.fn()} 
        evidenceId="test-evidence-123" 
        jobId="test-job-456" 
      />
    );
    
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        'http://localhost:8000/evidence/test-job-456/test-evidence-123'
      );
    });
  });
});
