#!/usr/bin/env python3
"""
Partition CloudTrail master database into 2-3 month chunks for AI security agent benchmarking/training.
"""

import argparse
import logging
from pathlib import Path

import duckdb
from rich.console import Console
from rich.logging import RichHandler

# Setup rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console)]
)
logger = logging.getLogger(__name__)

def get_monthly_data(conn):
    """Get monthly record counts from master database."""
    return conn.execute("""
        SELECT 
            DATE_TRUNC('month', eventtime) as month,
            COUNT(*) as count
        FROM cloudtrail_logs
        WHERE eventtime IS NOT NULL
        GROUP BY month
        ORDER BY month
    """).fetchall()

def create_partitions(monthly_data, target_months=3, high_activity_threshold=20000):
    """Create partition ranges from monthly data."""
    partitions = []
    current_start = None
    month_count = 0
    record_count = 0
    
    for month, count in monthly_data:
        if current_start is None:
            current_start = month
        
        month_count += 1
        record_count += count
        
        # Create partition when we hit target months or high activity
        if month_count >= target_months or count > high_activity_threshold:
            end_month = month.replace(day=28)  # Safe end-of-month
            name = f"customer_{current_start.strftime('%Y%m')}_{month.strftime('%Y%m')}"
            
            partitions.append((current_start, end_month, name, record_count))
            logger.info(f"Partition: {name} ({month_count} months, {record_count:,} records)")
            
            current_start = None
            month_count = 0
            record_count = 0
    
    return partitions

def create_partition_db(master_path, start_date, end_date, name, output_dir):
    """Create a single partition database."""
    partition_path = output_dir / f"{name}.duckdb"
    
    # Create partition database
    with duckdb.connect(str(partition_path)) as partition_conn:
        # Attach master and create table structure
        partition_conn.execute(f"ATTACH '{master_path}' AS master")
        partition_conn.execute("CREATE TABLE cloudtrail_logs AS SELECT * FROM master.cloudtrail_logs WHERE 1=0")
            
        # Copy data
        partition_conn.execute("""
            INSERT INTO cloudtrail_logs 
            SELECT * FROM master.cloudtrail_logs 
            WHERE eventtime >= ? AND eventtime <= ?
        """, [start_date, end_date])
        
        # Get count
        count = partition_conn.execute("SELECT COUNT(*) FROM cloudtrail_logs").fetchone()[0]
        logger.info(f"Created {name}: {count:,} records")
        
        # Basic indexes
        partition_conn.execute("CREATE INDEX idx_eventtime ON cloudtrail_logs(eventtime)")
        partition_conn.execute("CREATE INDEX idx_eventname ON cloudtrail_logs(eventname)")

def main():
    parser = argparse.ArgumentParser(description="Partition CloudTrail database")
    parser.add_argument("--master-db", type=Path, default="data/cloudtrail_master.duckdb")
    parser.add_argument("--output-dir", type=Path, default="data/partitions")
    parser.add_argument("--months", type=float, default=3, help="Months per partition")
    parser.add_argument("--high-activity", type=int, default=30000, help="Event threshold for high-activity partitions")
    
    args = parser.parse_args()
    
    if not args.master_db.exists():
        logger.error(f"Master database not found: {args.master_db}")
        return 1
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    with duckdb.connect(str(args.master_db)) as conn:
        monthly_data = get_monthly_data(conn)
        if not monthly_data:
            logger.error("No data found")
            return 1
        
        logger.info(f"Found data from {monthly_data[0][0]} to {monthly_data[-1][0]}")
        
        partitions = create_partitions(monthly_data, args.months, args.high_activity)
        
        for start_date, end_date, name, _ in partitions:
            create_partition_db(args.master_db, start_date, end_date, name, args.output_dir)
    
    logger.info(f"Created {len(partitions)} partition databases in {args.output_dir}")

if __name__ == "__main__":
    main()
