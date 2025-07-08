#!/usr/bin/env python3
"""
Simple validator for CloudTrail partition databases.
"""

import argparse
import logging
from pathlib import Path
import duckdb
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

# Setup rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console)]
)
logger = logging.getLogger(__name__)

def analyze_partition(db_path):
    """Get basic stats for a partition database."""
    with duckdb.connect(str(db_path)) as conn:
        stats = conn.execute("""
            SELECT 
                COUNT(*) as records,
                MIN(eventtime) as start_date,
                MAX(eventtime) as end_date,
                COUNT(DISTINCT eventname) as events,
                COUNT(DISTINCT eventsource) as services
            FROM cloudtrail_logs
        """).fetchone()
        
        return {
            'name': db_path.stem,
            'records': stats[0],
            'start_date': stats[1],
            'end_date': stats[2],
            'unique_events': stats[3],
            'unique_services': stats[4]
        }

def main():
    parser = argparse.ArgumentParser(description="Validate partition databases")
    parser.add_argument("--partitions-dir", type=Path, default="data/partitions")
    
    args = parser.parse_args()
    
    logger.info(f"Analyzing partition databases in {args.partitions_dir}")
    
    partition_files = list(args.partitions_dir.glob("customer_*.duckdb"))
    if not partition_files:
        logger.error(f"No partition files found in {args.partitions_dir}")
        return 1
    
    # Create rich table for results
    table = Table(title="CloudTrail Partition Analysis")
    table.add_column("Partition", style="cyan")
    table.add_column("Records", justify="right", style="green")
    table.add_column("Date Range", style="yellow")
    table.add_column("Events", justify="right", style="blue")
    table.add_column("Services", justify="right", style="magenta")
    
    total_records = 0
    
    for db_path in sorted(partition_files):
        try:
            stats = analyze_partition(db_path)
            total_records += stats['records']
            
            date_range = f"{stats['start_date'].strftime('%Y-%m-%d')} to {stats['end_date'].strftime('%Y-%m-%d')}"
            
            table.add_row(
                stats['name'],
                f"{stats['records']:,}",
                date_range,
                str(stats['unique_events']),
                str(stats['unique_services'])
            )
            
        except Exception as e:
            table.add_row(db_path.name, "[red]ERROR[/red]", str(e), "-", "-")
    
    console.print(table)
    logger.info(f"Total records across all partitions: {total_records:,}")

if __name__ == "__main__":
    main()
