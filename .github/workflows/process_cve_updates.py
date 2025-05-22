#!/usr/bin/env python3
import json
import os
import sys
import logging
import argparse
import boto3
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cve-monitor')

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Process CVE updates and filter by vendor')
    parser.add_argument('--delta-file', required=True, help='Path to delta.json file')
    parser.add_argument('--vendor-file', required=True, help='Path to vendors.txt file')
    parser.add_argument('--cve-batch-size', type=int, default=10, help='Number of CVEs to include in each Lambda invocation batch (default: 10)')
    return parser.parse_args()

def load_vendors(vendor_file):
    """Load the list of vendors to monitor from vendors.txt"""
    try:
        with open(vendor_file, 'r') as f:
            vendors = [line.strip().lower() for line in f if line.strip()]
        logger.info(f"Loaded {len(vendors)} vendors to monitor: {', '.join(vendors)}")
        return vendors
    except Exception as e:
        logger.error(f"Error loading vendors from {vendor_file}: {str(e)}")
        return []

def download_cve_file(cve_id, year, xxx_dir):
    """Download a CVE file from the local repository"""
    try:
        cve_path = f"cves/{year}/{xxx_dir}/CVE-{year}-{cve_id}.json"
        with open(cve_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading CVE file {cve_path}: {str(e)}")
        return None

def is_vendor_affected(cve_data, vendors):
    """Check if any of the monitored vendors are affected by this CVE"""
    if not cve_data or 'containers' not in cve_data:
        return False
    
    # Extract vendor information from the CVE data
    affected_vendors = []
    
    try:
        # The structure of the containers field can be either a list or a dictionary
        containers = cve_data.get('containers', {})
        
        # Handle the case where containers is a dictionary with 'cna' key
        if isinstance(containers, dict) and 'cna' in containers:
            cna_container = containers['cna']
        # Handle the case where containers is a list of container objects
        elif isinstance(containers, list):
            cna_container = next((c for c in containers if c.get('containerType') == 'cna'), None)
        else:
            cna_container = None
        
        if cna_container and 'affected' in cna_container:
            for affected in cna_container['affected']:
                vendor = affected.get('vendor', '').lower() if isinstance(affected, dict) else ''
                product = affected.get('product', '').lower() if isinstance(affected, dict) else ''
                
                if vendor:
                    affected_vendors.append(vendor)
                
                # Check if any of our monitored vendors match
                if any(v.lower() in [vendor, product] for v in vendors if vendor or product):
                    logger.info(f"Found matching vendor: {vendor} or product: {product}")
                    return True
    except Exception as e:
        logger.error(f"Error checking vendors in CVE data: {str(e)}")
        logger.error(f"CVE data structure: {type(cve_data)}")
        if isinstance(cve_data, dict):
            logger.error(f"Keys in CVE data: {cve_data.keys()}")
    
    if affected_vendors:
        logger.info(f"No matching vendors found among: {', '.join(affected_vendors)}")
    else:
        logger.info("No vendor information found in CVE data")
    return False

def process_cve_entries(entries, status, vendors):
    """Process a list of CVE entries and filter by vendor
    
    Args:
        entries: List of CVE entries from delta.json
        status: Status of the entries ('new' or 'updated')
        vendors: List of vendors to filter by
        
    Returns:
        List of processed CVE entries that match the vendor filter
    """
    processed_entries = []
    
    for cve_entry in entries:
        cve_id = cve_entry.get('cveId')
        if cve_id and cve_id.startswith('CVE-'):
            # Extract year and ID from CVE-YYYY-NNNNN format
            parts = cve_id.split('-')
            if len(parts) == 3:
                year = parts[1]
                id_num = parts[2]
                
                if len(id_num) <= 3:  # If ID is 3 digits or less
                    xxx_dir = "0xxx"
                else:
                    # Take all digits except the last 3
                    prefix = id_num[:-3]
                    xxx_dir = f"{prefix}xxx"
                
                cve_data = download_cve_file(id_num, year, xxx_dir)
                if cve_data and is_vendor_affected(cve_data, vendors):
                    processed_entries.append({
                        'cveId': cve_id,
                        'data': cve_data,
                        'status': status
                    })
    
    return processed_entries

def process_delta_json(delta_file, vendors):
    """Process the delta.json file and filter CVEs by vendor"""
    try:
        with open(delta_file, 'r') as f:
            delta_data = json.load(f)
        
        # Process new and updated CVEs
        cves_to_process = []
        
        # Process new CVEs
        new_cves = process_cve_entries(delta_data.get('new', []), 'new', vendors)
        cves_to_process.extend(new_cves)
        
        # Process updated CVEs
        updated_cves = process_cve_entries(delta_data.get('updated', []), 'updated', vendors)
        cves_to_process.extend(updated_cves)
        
        logger.info(f"Found {len(cves_to_process)} CVEs affecting monitored vendors")
        return cves_to_process
    
    except Exception as e:
        logger.error(f"Error processing delta.json file: {str(e)}")
        return []

def invoke_lambda_function(cves, batch_size=10):
    """
    Invoke the LanGuard-CVE-Update Lambda function with the filtered CVEs
    
    Args:
        cves: List of CVE entries that match the vendor filter
        batch_size: Number of CVEs to include in each Lambda invocation batch (default: 10)
    """
    try:
        # Check for AWS credentials in environment variables
        aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        aws_region = os.environ.get('AWS_REGION', 'us-east-1')
        
        if not aws_access_key or not aws_secret_key:
            logger.error("AWS credentials not found in environment variables")
            return
        
        # Initialize Lambda client with explicit credentials
        lambda_client = boto3.client(
            'lambda',
            region_name=aws_region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        
        # Split CVEs into batches based on the specified batch size without trimming any data
        total_cves = len(cves)
        num_batches = (total_cves + batch_size - 1) // batch_size  # Ceiling division
        
        logger.info(f"Splitting {total_cves} CVEs into {num_batches} batches of up to {batch_size} CVEs each")
        
        # Process each batch
        for i in range(num_batches):
            # Calculate the start and end indices for this batch
            start_idx = i * batch_size
            end_idx = min((i + 1) * batch_size, total_cves)
            
            # Create the batch
            batch = cves[start_idx:end_idx]
            
            # Prepare payload for this batch
            batch_payload = {
                'cves': batch
            }
            
            logger.info(f"Invoking Lambda function with batch {i+1}/{num_batches} ({len(batch)} CVEs)")
            
            # Invoke Lambda function with this batch
            response = lambda_client.invoke(
                FunctionName='LanGuard-CVE-Update',
                InvocationType='Event',  # Asynchronous invocation
                Payload=json.dumps(batch_payload)
            )
            
            logger.info(f"Batch {i+1}/{num_batches} status code: {response['StatusCode']}")
            
            # Add a small delay between batches to avoid throttling
            if i < num_batches - 1:
                time.sleep(1)
        
        
    except Exception as e:
        logger.error(f"Error invoking Lambda function: {str(e)}")
        
def main():
    """Main function to process CVE updates"""
    args = parse_arguments()
    
    delta_file = args.delta_file
    vendor_file = args.vendor_file
    
    if not os.path.exists(delta_file):
        logger.error(f"Delta file not found: {delta_file}")
        sys.exit(1)
    
    if not os.path.exists(vendor_file):
        logger.error(f"Vendor file not found: {vendor_file}")
        sys.exit(1)
    
    # Load vendors to monitor
    vendors = load_vendors(vendor_file)
    if not vendors:
        logger.error("No vendors to monitor, exiting")
        sys.exit(1)
    
    # Process delta.json and filter by vendor
    filtered_cves = process_delta_json(delta_file, vendors)
    
    if filtered_cves:
        logger.info(f"Found {len(filtered_cves)} CVEs affecting monitored vendors")
        # Send filtered CVEs to Lambda function
        invoke_lambda_function(filtered_cves, args.cve_batch_size)
    else:
        logger.info("No CVEs found affecting monitored vendors")

if __name__ == "__main__":
    main()
