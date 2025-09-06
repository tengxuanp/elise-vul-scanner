#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection
from unittest.mock import patch, MagicMock

# Test with mocked response
mock_response = MagicMock()
mock_response.content = b'<div>__ELISE__1234567890</div>'

with patch('httpx.Client') as mock_client:
    mock_client.return_value.__enter__.return_value.request.return_value = mock_response
    
    with patch('time.time', return_value=1234567890.123):
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        print(f'Result: {result}')
        print(f'Canary key: __ELISE__')
        print(f'Response content: {mock_response.content}')
        canary_bytes = b'__ELISE__'
        print(f'Canary in content: {canary_bytes in mock_response.content}')
