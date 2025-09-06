#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test what the function is actually checking
with patch('time.time', return_value=1234567890.123):
    full_canary = f"{CANARY_KEY}{int(1234567890.123*1000)}"
    
    # Test with response containing just the base canary
    mock_response1 = MagicMock()
    mock_response1.content = f'<div>{CANARY_KEY}</div>'.encode()
    
    # Test with response containing the full canary
    mock_response2 = MagicMock()
    mock_response2.content = f'<div>{full_canary}</div>'.encode()
    
    print(f"Full canary: {full_canary}")
    print(f"Base canary: {CANARY_KEY}")
    
    for i, mock_response in enumerate([mock_response1, mock_response2], 1):
        print(f"\nTest {i}:")
        print(f"Response content: {mock_response.content}")
        print(f"Base canary in response: {CANARY_KEY.encode() in mock_response.content}")
        print(f"Full canary in response: {full_canary.encode() in mock_response.content}")
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            result = classify_reflection(
                url='http://localhost:5001/search',
                method='GET',
                in_='query',
                param='q'
            )
            print(f'Function result: {result}')
