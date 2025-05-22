#!/usr/bin/env python3
import json
import os
import sys
import logging
import argparse

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
                xxx_dir = f"{id_num[:1]}xxx"
                
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
    
    logger.info(f"Filtered CVEs: {filtered_cves}")

if __name__ == "__main__":
    main()
