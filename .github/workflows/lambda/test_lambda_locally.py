#!/usr/bin/env python3
import json
import sys
import os
import logging
from lambda_function import lambda_handler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('lambda-test')

def main():
    """Test the Lambda function locally with test event data"""
    # Load the test event data
    test_event_path = os.path.join(os.path.dirname(__file__), 'test-event.json')
    
    try:
        with open(test_event_path, 'r') as f:
            test_event = json.load(f)
    except Exception as e:
        logger.error(f"Error loading test event data: {str(e)}")
        sys.exit(1)
    
    logger.info("Loaded test event data")
    logger.info(f"Test event contains {len(test_event.get('cves', []))} CVEs")
    
    # Create a mock context object
    class MockContext:
        def __init__(self):
            self.function_name = "LanGuard-CVE-Update"
            self.memory_limit_in_mb = 256
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:LanGuard-CVE-Update"
            self.aws_request_id = "test-request-id"
    
    context = MockContext()
    
    # Call the Lambda handler with the test event
    logger.info("Invoking Lambda handler with test event")
    response = lambda_handler(test_event, context)
    
    # Print the response
    logger.info("Lambda handler response:")
    logger.info(json.dumps(response, indent=2))
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
