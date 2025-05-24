#!/usr/bin/env python3
"""
Script to import flAWS CloudTrail logs into DuckDB for the security agent.

This script:
1. Reads compressed CloudTrail JSON log files from the flAWS dataset
2. Parses and normalizes the log entries
3. Creates a DuckDB database with optimized schema
4. Imports all log entries with proper indexing
"""

import argparse
import gzip
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import duckdb

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def create_database_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Create optimized schema for CloudTrail logs."""
    
    # Create main CloudTrail events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cloudtrail_events (
            -- Core event identification
            event_id VARCHAR PRIMARY KEY,
            event_time TIMESTAMP,
            event_name VARCHAR,
            event_source VARCHAR,
            event_version VARCHAR,
            
            -- User and authentication
            user_identity_type VARCHAR,
            user_identity_principal_id VARCHAR,
            user_identity_arn VARCHAR,
            user_identity_account_id VARCHAR,
            user_identity_access_key_id VARCHAR,
            user_identity_user_name VARCHAR,
            user_identity_session_context JSON,
            
            -- AWS context
            aws_region VARCHAR,
            source_ip_address VARCHAR,
            user_agent VARCHAR,
            
            -- Request details
            request_parameters JSON,
            response_elements JSON,
            
            -- Additional metadata
            request_id VARCHAR,
            error_code VARCHAR,
            error_message VARCHAR,
            
            -- Resources involved
            resources JSON,
            
            -- Service event info
            service_event_details JSON,
            
            -- Security and compliance
            api_version VARCHAR,
            management_event BOOLEAN,
            read_only BOOLEAN,
            recipient_account_id VARCHAR,
            
            -- Full record for complex queries
            raw_record JSON
        )
    """)
    
    # Create indexes for common query patterns
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_time ON cloudtrail_events(event_time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_name ON cloudtrail_events(event_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_source ON cloudtrail_events(event_source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_identity_arn ON cloudtrail_events(user_identity_arn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON cloudtrail_events(source_ip_address)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_aws_region ON cloudtrail_events(aws_region)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_error_code ON cloudtrail_events(error_code)")
    
    logger.info("Database schema created successfully")

def extract_user_identity(user_identity: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalize user identity information."""
    if not user_identity:
        return {}
    
    return {
        'user_identity_type': user_identity.get('type'),
        'user_identity_principal_id': user_identity.get('principalId'),
        'user_identity_arn': user_identity.get('arn'),
        'user_identity_account_id': user_identity.get('accountId'),
        'user_identity_access_key_id': user_identity.get('accessKeyId'),
        'user_identity_user_name': user_identity.get('userName'),
        'user_identity_session_context': json.dumps(user_identity.get('sessionContext')) if user_identity.get('sessionContext') else None
    }

def normalize_cloudtrail_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a CloudTrail record for database insertion."""
    
    # Extract user identity
    user_identity_fields = extract_user_identity(record.get('userIdentity', {}))
    
    # Parse event time
    event_time = None
    if record.get('eventTime'):
        try:
            event_time = datetime.fromisoformat(record['eventTime'].replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            logger.warning(f"Could not parse event time: {record.get('eventTime')}")
    
    # Build normalized record
    normalized = {
        'event_id': record.get('eventId'),
        'event_time': event_time,
        'event_name': record.get('eventName'),
        'event_source': record.get('eventSource'),
        'event_version': record.get('eventVersion'),
        
        'aws_region': record.get('awsRegion'),
        'source_ip_address': record.get('sourceIPAddress'),
        'user_agent': record.get('userAgent'),
        
        'request_parameters': json.dumps(record.get('requestParameters')) if record.get('requestParameters') else None,
        'response_elements': json.dumps(record.get('responseElements')) if record.get('responseElements') else None,
        
        'request_id': record.get('requestID'),
        'error_code': record.get('errorCode'),
        'error_message': record.get('errorMessage'),
        
        'resources': json.dumps(record.get('resources')) if record.get('resources') else None,
        'service_event_details': json.dumps(record.get('serviceEventDetails')) if record.get('serviceEventDetails') else None,
        
        'api_version': record.get('apiVersion'),
        'management_event': record.get('managementEvent'),
        'read_only': record.get('readOnly'),
        'recipient_account_id': record.get('recipientAccountId'),
        
        'raw_record': json.dumps(record)
    }
    
    # Add user identity fields
    normalized.update(user_identity_fields)
    
    return normalized

def process_log_file(file_path: str) -> List[Dict[str, Any]]:
    """Process a single CloudTrail log file."""
    logger.info(f"Processing file: {file_path}")
    
    records = []
    
    try:
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Parse JSON record
                    record = json.loads(line)
                    
                    # Handle both individual records and Records array format
                    if 'Records' in record:
                        # CloudTrail format with Records array
                        for event_record in record['Records']:
                            normalized = normalize_cloudtrail_record(event_record)
                            if normalized.get('event_id'):  # Only add if we have an event ID
                                records.append(normalized)
                    else:
                        # Individual record format
                        normalized = normalize_cloudtrail_record(record)
                        if normalized.get('event_id'):
                            records.append(normalized)
                
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON decode error in {file_path}:{line_num} - {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing record in {file_path}:{line_num} - {e}")
                    continue
    
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []
    
    logger.info(f"Processed {len(records)} records from {file_path}")
    return records

def import_cloudtrail_logs(db_path: str|Path, cloudtrail_logs_dir: str|Path) -> None:
    """Main function to import all CloudTrail logs into DuckDB."""
    
    # Connect to DuckDB
    conn = duckdb.connect(db_path)
    logger.info(f"Connected to DuckDB at {db_path}")
    
    try:
        # Create schema
        create_database_schema(conn)
        
        # Get all CloudTrail log files
        log_files = list(Path(cloudtrail_logs_dir).rglob("*.json.gz"))
        log_files.sort()  # Process in order
        
        if not log_files:
            logger.error(f"No CloudTrail log files found in {cloudtrail_logs_dir}")
            return
        
        logger.info(f"Found {len(log_files)} CloudTrail log files")
        
        total_records = 0
        
        # Process each file
        for file_path in log_files:
            records = process_log_file(file_path)
            
            if records:
                # Insert records into database
                try:
                    # Prepare insert statement
                    insert_sql = """
                        INSERT INTO cloudtrail_events (
                            event_id, event_time, event_name, event_source, event_version,
                            user_identity_type, user_identity_principal_id, user_identity_arn,
                            user_identity_account_id, user_identity_access_key_id, user_identity_user_name,
                            user_identity_session_context, aws_region, source_ip_address, user_agent,
                            request_parameters, response_elements, request_id, error_code, error_message,
                            resources, service_event_details, api_version, management_event, read_only,
                            recipient_account_id, raw_record
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                    
                    # Convert records to tuples for insertion
                    insert_data = []
                    for record in records:
                        insert_data.append((
                            record.get('event_id'),
                            record.get('event_time'),
                            record.get('event_name'),
                            record.get('event_source'),
                            record.get('event_version'),
                            record.get('user_identity_type'),
                            record.get('user_identity_principal_id'),
                            record.get('user_identity_arn'),
                            record.get('user_identity_account_id'),
                            record.get('user_identity_access_key_id'),
                            record.get('user_identity_user_name'),
                            record.get('user_identity_session_context'),
                            record.get('aws_region'),
                            record.get('source_ip_address'),
                            record.get('user_agent'),
                            record.get('request_parameters'),
                            record.get('response_elements'),
                            record.get('request_id'),
                            record.get('error_code'),
                            record.get('error_message'),
                            record.get('resources'),
                            record.get('service_event_details'),
                            record.get('api_version'),
                            record.get('management_event'),
                            record.get('read_only'),
                            record.get('recipient_account_id'),
                            record.get('raw_record')
                        ))
                    
                    # Execute batch insert
                    conn.executemany(insert_sql, insert_data)
                    total_records += len(records)
                    logger.info(f"Inserted {len(records)} records from {os.path.basename(file_path)}")
                    
                except Exception as e:
                    logger.error(f"Error inserting records from {file_path}: {e}")
                    continue
        
        # Commit and get final statistics
        conn.commit()
        
        # Get database statistics
        stats = conn.execute("SELECT COUNT(*) as total_events FROM cloudtrail_events").fetchone()
        unique_events = conn.execute("SELECT COUNT(DISTINCT event_name) as unique_events FROM cloudtrail_events").fetchone()
        date_range = conn.execute("""
            SELECT 
                MIN(event_time) as earliest_event, 
                MAX(event_time) as latest_event 
            FROM cloudtrail_events 
            WHERE event_time IS NOT NULL
        """).fetchone()
        
        logger.info("="*50)
        logger.info("DATABASE IMPORT COMPLETED SUCCESSFULLY")
        logger.info("="*50)
        logger.info(f"Total records imported: {stats[0]}")
        logger.info(f"Unique event types: {unique_events[0]}")
        logger.info(f"Date range: {date_range[0]} to {date_range[1]}")
        logger.info(f"Database location: {db_path}")
        
        # Show sample of event types
        logger.info("\nTop 10 most common event types:")
        top_events = conn.execute("""
            SELECT event_name, COUNT(*) as count 
            FROM cloudtrail_events 
            GROUP BY event_name 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        
        for event_name, count in top_events:
            logger.info(f"  {event_name}: {count}")
        
    except Exception as e:
        logger.error(f"Fatal error during import: {e}")
        raise
    
    finally:
        conn.close()

def verify_database(db_path: str|Path) -> None:
    """Verify the database was created correctly."""
    logger.info("Verifying database...")
    
    conn = duckdb.connect(db_path)
    
    try:
        # Test basic queries
        result = conn.execute("SELECT COUNT(*) FROM cloudtrail_events").fetchone()
        logger.info(f"Total events in database: {result[0]}")
        
        # Test some sample queries that the agent will use
        sample_queries = [
            "SELECT DISTINCT event_source FROM cloudtrail_events LIMIT 5",
            "SELECT DISTINCT aws_region FROM cloudtrail_events WHERE aws_region IS NOT NULL LIMIT 5",
            "SELECT event_name, COUNT(*) FROM cloudtrail_events GROUP BY event_name ORDER BY COUNT(*) DESC LIMIT 5"
        ]
        
        for query in sample_queries:
            result = conn.execute(query).fetchall()
            logger.info(f"Query: {query}")
            logger.info(f"Result: {result}")
            logger.info("-" * 30)
            
    except Exception as e:
        logger.error(f"Database verification failed: {e}")
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    logger.info("CloudTrail Logs Import Script")
    logger.info("=" * 40)
    
    parser = argparse.ArgumentParser(description="Import flAWS CloudTrail logs into DuckDB.")
    parser.add_argument('--cloudtrail-logs-dir', type=str, default="data/flaws/data/flaws_cloudtrail_logs",
                        help="Directory containing CloudTrail logs (default: data/flaws/data/flaws_cloudtrail_logs)")
    parser.add_argument('--db-path', type=str, default="data/flaws_cloudtrail_logs.duckdb",
                        help="Path to the DuckDB database file (default: data/cloudtrail_logs.duckdb)")
    args = parser.parse_args()
    cloudtrail_logs_dir = Path(args.cloudtrail_logs_dir)
    db_path = Path(args.db_path)
    # Ensure data directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if source directory exists
    if not Path(cloudtrail_logs_dir).exists():
        logger.error(f"Source directory not found: {cloudtrail_logs_dir}")
        exit(1)
    
    try:
        # Import logs
        import_cloudtrail_logs(db_path=db_path, cloudtrail_logs_dir=cloudtrail_logs_dir)
        
        # Verify the import
        verify_database(db_path=db_path)
        
        logger.info("\n✅ CloudTrail logs successfully imported into DuckDB!")
        logger.info(f"Database location: {db_path}")
        logger.info("\nYou can now use the database for training and queries.")
        
    except KeyboardInterrupt:
        logger.info("Import interrupted by user")
    except Exception as e:
        logger.error(f"Import failed: {e}")
        exit(1)
