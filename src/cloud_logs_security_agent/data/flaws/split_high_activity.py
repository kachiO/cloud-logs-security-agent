#!/usr/bin/env python3
"""
Split high-activity partition into smaller daily or weekly chunks.
"""

import argparse
import logging
from datetime import timedelta
from pathlib import Path
import duckdb
from rich.console import Console
from rich.logging import RichHandler

console = Console()
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[RichHandler(console=console)])
logger = logging.getLogger(__name__)

def analyze_high_activity_partition(db_path):
    """Analyze daily distribution in the high-activity partition."""
    with duckdb.connect(str(db_path)) as conn:
        daily_counts = conn.execute("""
            SELECT 
                DATE_TRUNC('day', eventtime) as day,
                COUNT(*) as count
            FROM cloudtrail_logs
            GROUP BY day
            ORDER BY day
        """).fetchall()
        
        logger.info(f"Daily breakdown for {db_path.name}:")
        for day, count in daily_counts:
            logger.info(f"  {day.strftime('%Y-%m-%d')}: {count:,} events")
        
        return daily_counts

def split_by_days(source_db, output_dir, max_events_per_partition=50000):
    """Split partition into daily chunks, combining days if under threshold."""
    daily_data = analyze_high_activity_partition(source_db)
    
    partitions = []
    current_start = None
    current_events = 0
    day_count = 0
    
    for day, count in daily_data:
        if current_start is None:
            current_start = day
        
        current_events += count
        day_count += 1
        
        # Create partition if we hit the event limit or it's a very high single day
        if current_events >= max_events_per_partition or count > max_events_per_partition:
            end_day = day
            name = f"customer_incident_{current_start.strftime('%Y%m%d')}"
            if day_count > 1:
                name += f"_to_{end_day.strftime('%Y%m%d')}"
            
            partitions.append((current_start, end_day, name, current_events))
            logger.info(f"Will create: {name} ({day_count} days, {current_events:,} events)")
            
            current_start = None
            current_events = 0
            day_count = 0
    
    # Create the actual partition files
    with duckdb.connect(str(source_db)) as source_conn:
        for start_date, end_date, name, expected_count in partitions:
            partition_path = output_dir / f"{name}.duckdb"
            
            with duckdb.connect(str(partition_path)) as partition_conn:
                partition_conn.execute(f"ATTACH '{source_db}' AS source")
                partition_conn.execute("CREATE TABLE cloudtrail_logs AS SELECT * FROM source.cloudtrail_logs WHERE 1=0")
                
                # Copy data for this date range
                end_date_plus_one = end_date + timedelta(days=1)
                partition_conn.execute("""
                    INSERT INTO cloudtrail_logs 
                    SELECT * FROM source.cloudtrail_logs 
                    WHERE eventtime >= ? AND eventtime < ?
                """, [start_date, end_date_plus_one])
                
                actual_count = partition_conn.execute("SELECT COUNT(*) FROM cloudtrail_logs").fetchone()[0]
                logger.info(f"Created {name}: {actual_count:,} events")
                
                # Add indexes
                partition_conn.execute("CREATE INDEX idx_eventtime ON cloudtrail_logs(eventtime)")
                partition_conn.execute("CREATE INDEX idx_eventname ON cloudtrail_logs(eventname)")

def main():
    parser = argparse.ArgumentParser(description="Split high-activity partition")
    parser.add_argument("--source-db", type=Path, required=True, help="High-activity partition to split")
    parser.add_argument("--output-dir", type=Path, help="Output directory for new partitions")
    parser.add_argument("--max-events", type=int, default=50000, help="Max events per new partition")
    parser.add_argument("--analyze-only", action="store_true", help="Just analyze, don't create partitions")
    
    args = parser.parse_args()
    
    if not args.source_db.exists():
        logger.error(f"Source database not found: {args.source_db}")
        return 1
    
    if args.analyze_only:
        analyze_high_activity_partition(args.source_db)
        return 0
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    split_by_days(args.source_db, args.output_dir, args.max_events)
    logger.info("High-activity partition split complete!")

if __name__ == "__main__":
    main()
