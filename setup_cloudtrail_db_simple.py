#!/usr/bin/env python3
"""
Simple script to import flAWS CloudTrail logs into DuckDB.
Uses DuckDB's automatic JSON inference for simplicity.
"""

import argparse
import logging
from pathlib import Path

import duckdb

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def import_cloudtrail_logs_simple(db_path:str|Path, cloudtrail_logs_dir:str|Path) -> None:
    """Simple import using DuckDB's automatic JSON handling."""

    # Connect to DuckDB
    conn = duckdb.connect(db_path)
    logger.info(f"Connected to DuckDB at {db_path}")
    
    try:
        # Let DuckDB automatically infer the schema from JSON files
        logger.info("Creating table from JSON files...")
        
        # Set larger maximum_object_size to handle large JSON files
        conn.execute("SET maximum_object_size='128MB'")
        logger.info("Set maximum_object_size to 128MB")
        
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS cloudtrail_events AS 
            SELECT * FROM read_json_auto('{cloudtrail_logs_dir}/*.json.gz')
        """)
        
        # Get statistics
        stats = conn.execute("SELECT COUNT(*) as total_events FROM cloudtrail_events").fetchone()
        logger.info(f"Total records imported: {stats[0]}")
        
        # Show sample of what we have
        logger.info("Sample columns in the table:")
        columns = conn.execute("DESCRIBE cloudtrail_events").fetchall()
        for col_name, col_type, *_ in columns[:10]:  # Show first 10 columns
            logger.info(f"  {col_name}: {col_type}")
        
        if len(columns) > 10:
            logger.info(f"  ... and {len(columns) - 10} more columns")
        
        # Test a simple query
        sample = conn.execute("SELECT * FROM cloudtrail_events LIMIT 1").fetchone()
        logger.info(f"Sample record keys: {len(sample) if sample else 0} fields")
        
        logger.info("✅ CloudTrail logs successfully imported!")
        
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    logger.info("Simple CloudTrail Logs Import Script")
    logger.info("=" * 40)
    parser = argparse.ArgumentParser(description="Import flAWS CloudTrail logs into DuckDB.")
    parser.add_argument('--cloudtrail-logs-dir', type=str, default="data/flaws/data/flaws_cloudtrail_logs",
                        help="Directory containing CloudTrail logs (default: data/flaws/data/flaws_cloudtrail_logs)")
    parser.add_argument('--db-path', type=str, default="data/flaws_cloudtrail_logs_simple-schema.duckdb",
                        help="Path to the DuckDB database file (default: data/cloudtrail_logs.duckdb)")
    args = parser.parse_args()
    cloudtrail_logs_dir = Path(args.cloudtrail_logs_dir)
    db_path = Path(args.db_path)
    # Ensure data directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if source directory exists
    if not Path(cloudtrail_logs_dir):
        logger.error(f"Source directory not found: {cloudtrail_logs_dir}")
        exit(1)
    
    try:
        import_cloudtrail_logs_simple(db_path=db_path, cloudtrail_logs_dir=cloudtrail_logs_dir)
        logger.info(f"\nDatabase location: {db_path}")
        logger.info("You can now query the data using DuckDB!")
        
    except Exception as e:
        logger.error(f"Import failed: {e}")
        exit(1)
