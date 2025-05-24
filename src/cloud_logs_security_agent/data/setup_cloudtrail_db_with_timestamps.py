#!/usr/bin/env python3
"""
Rebuild the CloudTrail database with proper timestamp handling.
This ensures eventTime is created as TIMESTAMP from the start.
"""

import argparse
import gzip
import json
import logging
from pathlib import Path
import duckdb
import pandas as pd
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def load_json_gz_with_timestamp_fix(file_path: str | Path) -> list:
    """Load all records from a CloudTrail JSON.gz file with timestamp conversion."""
    try:
        with gzip.open(file_path, "rt", encoding="utf-8") as f:
            data = json.load(f)
        
        records = data.get("Records", [data] if isinstance(data, dict) else data)
        
        # Fix timestamp format for each record
        for record in records:
            if 'eventTime' in record:
                # Convert to proper datetime object
                try:
                    # Handle CloudTrail timestamp format: 2023-01-01T12:00:00Z
                    timestamp_str = record['eventTime']
                    if timestamp_str.endswith('Z'):
                        timestamp_str = timestamp_str[:-1] + '+00:00'
                    record['eventTime'] = datetime.fromisoformat(timestamp_str)
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Could not parse timestamp {record.get('eventTime')}: {e}")
                    # Keep original value if parsing fails
        
        return records
            
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        return []

def rebuild_database_with_proper_schema(db_path: str | Path, cloudtrail_logs_dir: str | Path) -> None:
    """Rebuild database ensuring proper timestamp handling."""
    
    # Remove existing database
    if Path(db_path).exists():
        Path(db_path).unlink()
        logger.info(f"Removed existing database: {db_path}")
    
    conn = duckdb.connect(db_path)
    logger.info(f"Creating new database at {db_path}")

    try:
        # Get all JSON files
        json_files = list(Path(cloudtrail_logs_dir).rglob("*.json.gz"))
        json_files.sort()
        logger.info(f"Found {len(json_files)} CloudTrail files to process")

        if not json_files:
            raise Exception(f"No JSON files found in {cloudtrail_logs_dir}")

        # Process all files and collect records
        all_records = []
        for file in json_files:
            file_records = load_json_gz_with_timestamp_fix(file)
            all_records.extend(file_records)
            logger.info(f"Loaded {len(file_records)} records from {file}")
        
        logger.info(f"Total records collected: {len(all_records)}")
        
        # Create DataFrame - pandas will properly handle datetime objects
        df = pd.DataFrame(all_records)
        logger.info(f"DataFrame created with shape: {df.shape}")
        
        # Check eventTime column type in DataFrame
        if 'eventTime' in df.columns:
            logger.info(f"eventTime column type in DataFrame: {df['eventTime'].dtype}")

        # Import into DuckDB - this should preserve the TIMESTAMP type
        conn.execute("CREATE TABLE cloudtrail_events AS SELECT * FROM df")
        
        # Verify the schema
        schema = conn.execute("DESCRIBE cloudtrail_events").fetchall()
        eventTime_info = [col for col in schema if col[0] == 'eventTime']
        if eventTime_info:
            logger.info(f"✅ eventTime column type in DuckDB: {eventTime_info[0][1]}")
        
        # Create indexes for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_eventTime ON cloudtrail_events(eventTime)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_eventName ON cloudtrail_events(eventName)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_eventSource ON cloudtrail_events(eventSource)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sourceIPAddress ON cloudtrail_events(sourceIPAddress)")
        logger.info("✅ Created performance indexes")

        # Get final statistics
        stats = conn.execute("SELECT COUNT(*) FROM cloudtrail_events").fetchone()
        logger.info(f"✅ Total records in database: {stats[0]:,}")
        
        # Test timestamp queries
        try:
            recent = conn.execute("SELECT eventTime FROM cloudtrail_events ORDER BY eventTime DESC LIMIT 3").fetchall()
            logger.info("✅ Sample recent timestamps:")
            for row in recent:
                logger.info(f"  {row[0]}")
        except Exception as e:
            logger.warning(f"Could not query timestamps: {e}")

        logger.info("✅ Database rebuilt successfully with proper TIMESTAMP handling!")

    except Exception as e:
        logger.error(f"Database rebuild failed: {e}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rebuild CloudTrail database with proper timestamp handling")
    parser.add_argument('--cloudtrail-logs-dir', type=str, default="data/flaws/data/flaws_cloudtrail_logs")
    parser.add_argument('--db-path', type=str, default="data/flaws_cloudtrail_logs_fixed.duckdb")
    
    args = parser.parse_args()
    
    try:
        rebuild_database_with_proper_schema(Path(args.db_path), Path(args.cloudtrail_logs_dir))
        logger.info(f"New database with proper timestamps: {args.db_path}")
    except Exception as e:
        logger.error(f"Rebuild failed: {e}")
        exit(1)
