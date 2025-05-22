import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda handler for processing CVE updates
    
    This function receives CVE data from the GitHub Actions workflow,
    processes it, and performs necessary actions like updating a database
    or sending notifications.
    
    Args:
        event: The event data containing CVE information
        context: Lambda execution context
    
    Returns:
        Response object indicating success or failure
    """
    logger.info("Received CVE update event")
    
    try:
        # Extract CVE data from the event
        if 'body' in event:
            # Handle API Gateway event structure
            try:
                body = json.loads(event['body'])
                cves = body.get('cves', [])
            except json.JSONDecodeError:
                logger.error("Failed to parse request body as JSON")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Invalid JSON in request body'})
                }
        else:
            # Direct invocation
            cves = event.get('cves', [])
        
        if not cves:
            logger.info("No CVEs to process")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No CVEs to process'})
            }
        
        logger.info(f"Processing {len(cves)} CVEs")
        
        # Process each CVE
        for cve in cves:
            process_cve(cve)
        
        # Return success response
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully processed {len(cves)} CVEs',
                'processed_count': len(cves)
            })
        }
    
    except Exception as e:
        logger.error(f"Error processing CVE updates: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def process_cve(cve):
    """
    Process a single CVE entry
    
    Args:
        cve: Dictionary containing CVE data
    """
    cve_id = cve.get('cveId')
    status = cve.get('status')  # 'new' or 'updated'
    data = cve.get('data', {})
    
    logger.info(f"Processing CVE {cve_id} (status: {status})")
    
    # Extract relevant information from the CVE data
    try:
        # Get the CNA container which contains the vulnerability details
        containers = data.get('containers', {})
        
        if isinstance(containers, dict) and 'cna' in containers:
            cna_container = containers['cna']
        elif isinstance(containers, list):
            cna_container = next((c for c in containers if c.get('containerType') == 'cna'), None)
        else:
            cna_container = None
        
        if not cna_container:
            logger.warning(f"No CNA container found for {cve_id}")
            return
        
        # Extract vulnerability details
        title = cna_container.get('title', '')
        description = ''
        
        # Get description from descriptions if available
        descriptions = cna_container.get('descriptions', [])
        if descriptions and isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
        
        # Get affected products
        affected_products = []
        affected_items = cna_container.get('affected', [])
        
        if affected_items and isinstance(affected_items, list):
            for item in affected_items:
                if isinstance(item, dict):
                    vendor = item.get('vendor', '')
                    product = item.get('product', '')
                    versions = []
                    
                    # Extract version information
                    version_data = item.get('versions', [])
                    if version_data and isinstance(version_data, list):
                        for ver in version_data:
                            if isinstance(ver, dict):
                                version = ver.get('version', '')
                                status = ver.get('status', '')
                                if version:
                                    versions.append({
                                        'version': version,
                                        'status': status
                                    })
                    
                    affected_products.append({
                        'vendor': vendor,
                        'product': product,
                        'versions': versions
                    })
        
        # Get problem types (CWEs)
        problem_types = []
        problem_type_data = cna_container.get('problemTypes', [])
        
        if problem_type_data and isinstance(problem_type_data, list):
            for pt in problem_type_data:
                if isinstance(pt, dict) and 'descriptions' in pt:
                    for desc in pt.get('descriptions', []):
                        if isinstance(desc, dict) and desc.get('type') == 'CWE':
                            cwe_id = desc.get('cweId', '')
                            description_text = desc.get('description', '')
                            if cwe_id:
                                problem_types.append({
                                    'cwe_id': cwe_id,
                                    'description': description_text
                                })
        
        # Get references
        references = []
        refs_data = cna_container.get('references', [])
        
        if refs_data and isinstance(refs_data, list):
            for ref in refs_data:
                if isinstance(ref, dict):
                    url = ref.get('url', '')
                    name = ref.get('name', '')
                    if url:
                        references.append({
                            'url': url,
                            'name': name
                        })
        
        # Create a structured record for the CVE
        cve_record = {
            'cve_id': cve_id,
            'status': status,
            'title': title,
            'description': description,
            'affected_products': affected_products,
            'problem_types': problem_types,
            'references': references,
            'last_updated': data.get('cveMetadata', {}).get('dateUpdated', '')
        }
        
        # Print the CVE record details
        store_cve_record(cve_record)
        
    except Exception as e:
        logger.error(f"Error processing CVE {cve_id}: {str(e)}")

def store_cve_record(cve_record):
    """
    Print the CVE record details instead of storing in DynamoDB
    
    Args:
        cve_record: Dictionary containing structured CVE data
    """
    try:
        # Print the CVE record in a formatted way
        logger.info(f"\n{'='*80}\nCVE DETAILS: {cve_record['cve_id']}\n{'='*80}")
        logger.info(f"Title: {cve_record['title']}")
        logger.info(f"Status: {cve_record['status']}")
        logger.info(f"Description: {cve_record['description']}")
        
        # Print affected products
        logger.info("\nAffected Products:")
        for product in cve_record['affected_products']:
            versions_str = ', '.join([v['version'] for v in product['versions']]) if product['versions'] else 'N/A'
            logger.info(f"  - {product['vendor']} {product['product']} (versions: {versions_str})")
        
        # Print problem types (CWEs)
        if cve_record['problem_types']:
            logger.info("\nProblem Types:")
            for pt in cve_record['problem_types']:
                logger.info(f"  - {pt['cwe_id']}: {pt['description']}")
        
        # Print references
        if cve_record['references']:
            logger.info("\nReferences:")
            for ref in cve_record['references']:
                logger.info(f"  - {ref['name'] or 'Link'}: {ref['url']}")
                
        logger.info(f"Last Updated: {cve_record['last_updated']}")
        logger.info(f"{'='*80}\n")
        
    except Exception as e:
        logger.error(f"Error printing CVE {cve_record.get('cve_id', 'unknown')}: {str(e)}")
