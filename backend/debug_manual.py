#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test the actual function call with manual debugging
with patch('time.time', return_value=1234567890.123):
    full_canary = f"{CANARY_KEY}{int(1234567890.123*1000)}"
    mock_response = MagicMock()
    mock_response.content = f'<div>{full_canary}</div>'.encode()
    
    print(f"Testing function call...")
    print(f"Full canary: {full_canary}")
    
    # Mock the httpx.Client to capture the request
    with patch('httpx.Client') as mock_client:
        client_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = client_instance
        client_instance.request.return_value = mock_response
        
        # Call the function with explicit parameters
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        
        print(f'Function result: {result}')
        print(f"Request called: {client_instance.request.called}")
        
        # Check what request was made
        if client_instance.request.called:
            call_args = client_instance.request.call_args
            print(f"Request args: {call_args}")
        else:
            print("No request was made - function returned early")
            
        # Let's also check if the function is being called at all
        print(f"Mock client called: {mock_client.called}")
        print(f"Client instance created: {client_instance is not None}")
        
        # Let's check if the function is being called at all
        print(f"Mock client called: {mock_client.called}")
        print(f"Client instance created: {client_instance is not None}")
        
        # Let's check if the function is being called at all
        print(f"Mock client called: {mock_client.called}")
        print(f"Client instance created: {client_instance is not None}")
