#!/usr/bin/env uv run python3
"""
Create DuckDB database from CloudTrail logs with Athena-aligned schema
"""

import argparse
import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import duckdb
from pydantic import BaseModel
from rich.console import Console
from rich.logging import RichHandler
from tqdm import tqdm

# Setup rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console)]
)
logger = logging.getLogger(__name__)

# Pydantic models for CloudTrail records
class SessionAttributes(BaseModel):
    mfaauthenticated: Optional[str] = None
    creationdate: Optional[str] = None

class SessionIssuer(BaseModel):
    type: Optional[str] = None
    principalId: Optional[str] = None
    arn: Optional[str] = None
    accountId: Optional[str] = None
    userName: Optional[str] = None

class SessionContext(BaseModel):
    attributes: Optional[SessionAttributes] = None
    sessionissuer: Optional[SessionIssuer] = None

class UserIdentity(BaseModel):
    type: Optional[str] = None
    principalid: Optional[str] = None
    arn: Optional[str] = None
    accountid: Optional[str] = None
    invokedby: Optional[str] = None
    accesskeyid: Optional[str] = None
    userName: Optional[str] = None
    sessioncontext: Optional[SessionContext] = None

class Resource(BaseModel):
    ARN: Optional[str] = None
    accountId: Optional[str] = None
    type: Optional[str] = None

class CloudTrailRecord(BaseModel):
    eventversion: Optional[str] = None
    useridentity: Optional[UserIdentity] = None
    eventtime: Optional[datetime] = None
    eventsource: Optional[str] = None
    eventname: Optional[str] = None
    awsregion: Optional[str] = None
    sourceipaddress: Optional[str] = None
    useragent: Optional[str] = None
    errorcode: Optional[str] = None
    errormessage: Optional[str] = None
    requestparameters: Optional[str] = None
    responseelements: Optional[str] = None
    additionaleventdata: Optional[str] = None
    requestid: Optional[str] = None
    eventid: Optional[str] = None
    resources: Optional[List[Resource]] = None
    eventtype: Optional[str] = None
    apiversion: Optional[str] = None
    readonly: Optional[str] = None
    recipientaccountid: Optional[str] = None
    serviceeventdetails: Optional[str] = None
    sharedeventid: Optional[str] = None
    vpcendpointid: Optional[str] = None

def create_cloudtrail_table(conn):
    """Create CloudTrail table with Athena-aligned schema"""
    
    # DuckDB schema adapted from Athena CREATE TABLE
    schema_sql = """
    CREATE TABLE cloudtrail_logs (
        eventversion VARCHAR,
        useridentity STRUCT(
            type VARCHAR,
            principalid VARCHAR,
            arn VARCHAR,
            accountid VARCHAR,
            invokedby VARCHAR,
            accesskeyid VARCHAR,
            userName VARCHAR,
            sessioncontext STRUCT(
                attributes STRUCT(
                    mfaauthenticated VARCHAR,
                    creationdate VARCHAR
                ),
                sessionissuer STRUCT(
                    type VARCHAR,
                    principalId VARCHAR,
                    arn VARCHAR,
                    accountId VARCHAR,
                    userName VARCHAR
                )
            )
        ),
        eventtime TIMESTAMP,
        eventsource VARCHAR,
        eventname VARCHAR,
        awsregion VARCHAR,
        sourceipaddress VARCHAR,
        useragent VARCHAR,
        errorcode VARCHAR,
        errormessage VARCHAR,
        requestparameters VARCHAR,  -- JSON string
        responseelements VARCHAR,   -- JSON string
        additionaleventdata VARCHAR,
        requestid VARCHAR,
        eventid VARCHAR,
        resources STRUCT(
            ARN VARCHAR,
            accountId VARCHAR,
            type VARCHAR
        )[],
        eventtype VARCHAR,
        apiversion VARCHAR,
        readonly VARCHAR,
        recipientaccountid VARCHAR,
        serviceeventdetails VARCHAR,
        sharedeventid VARCHAR,
        vpcendpointid VARCHAR
    )
    """
    
    logger.info("Creating CloudTrail table with Athena-aligned schema...")
    conn.execute(schema_sql)
    logger.info("Table created successfully")

def process_cloudtrail_file(conn, file_path):
    """Process a single CloudTrail JSON.gz file"""
    
    logger.info(f"Processing {file_path}...")
    
    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    
    records = data.get('Records', [])
    if not records:
        logger.warning(f"No records found in {file_path}")
        return 0
    
    total_inserted = 0
    processed_batch = []
    
    for record in tqdm(records, desc=f"Processing {file_path.name}", unit="record"):
        
        try:
            cloudtrail_record = CloudTrailRecord(
                eventversion=record.get('eventVersion'),
                useridentity=extract_user_identity(record.get('userIdentity', {})),
                eventtime=convert_timestamp(record.get('eventTime')),
                eventsource=record.get('eventSource'),
                eventname=record.get('eventName'),
                awsregion=record.get('awsRegion'),
                sourceipaddress=record.get('sourceIPAddress'),
                useragent=record.get('userAgent'),
                errorcode=record.get('errorCode'),
                errormessage=record.get('errorMessage'),
                requestparameters=json.dumps(record.get('requestParameters')) if record.get('requestParameters') else None,
                responseelements=json.dumps(record.get('responseElements')) if record.get('responseElements') else None,
                additionaleventdata=json.dumps(record.get('additionalEventData')) if record.get('additionalEventData') else None,
                requestid=record.get('requestID'),
                eventid=record.get('eventID'),
                resources=extract_resources(record.get('resources', [])),
                eventtype=record.get('eventType'),
                apiversion=record.get('apiVersion'),
                readonly=str(record.get('readOnly')) if record.get('readOnly') is not None else None,
                recipientaccountid=record.get('recipientAccountId'),
                serviceeventdetails=json.dumps(record.get('serviceEventDetails')) if record.get('serviceEventDetails') else None,
                sharedeventid=record.get('sharedEventID'),
                vpcendpointid=record.get('vpcEndpointId')
            )
            
            processed_batch.append(cloudtrail_record.model_dump())
        except Exception as e:
            logger.warning(f"Failed to create CloudTrail record: {e}")
            continue
    
    # Insert all records at once
    try:
        conn.executemany("""
            INSERT INTO cloudtrail_logs VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, [tuple(r.values()) for r in processed_batch])
        
        total_inserted = len(processed_batch)
        
    except Exception as e:
        logger.error(f"Error inserting records: {e}")
        # Try inserting records individually to identify problematic ones
        for record in processed_batch:
            try:
                conn.execute("""
                    INSERT INTO cloudtrail_logs VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, tuple(record.values()))
                total_inserted += 1
            except Exception as e2:
                logger.warning(f"Skipping record due to error: {e2}")
    
    logger.info(f"Inserted {total_inserted} records from {file_path}")
    return total_inserted

def extract_user_identity(user_identity):
    """Extract user identity struct using Pydantic"""
    if not user_identity:
        return None
    
    session_context = user_identity.get('sessionContext', {})
    attributes = session_context.get('attributes', {})
    session_issuer = session_context.get('sessionIssuer', {})
    
    try:
        return UserIdentity(
            type=user_identity.get('type'),
            principalid=user_identity.get('principalId'),
            arn=user_identity.get('arn'),
            accountid=user_identity.get('accountId'),
            invokedby=user_identity.get('invokedBy'),
            accesskeyid=user_identity.get('accessKeyId'),
            userName=user_identity.get('userName'),
            sessioncontext=SessionContext(
                attributes=SessionAttributes(
                    mfaauthenticated=attributes.get('mfaAuthenticated'),
                    creationdate=attributes.get('creationDate')
                ),
                sessionissuer=SessionIssuer(
                    type=session_issuer.get('type'),
                    principalId=session_issuer.get('principalId'),
                    arn=session_issuer.get('arn'),
                    accountId=session_issuer.get('accountId'),
                    userName=session_issuer.get('userName')
                )
            )
        )
    except Exception as e:
        logger.warning(f"Failed to create UserIdentity: {e}")
        return None

def extract_resources(resources):
    """Extract resources array using Pydantic"""
    if not resources:
        return []
    
    try:
        return [
            Resource(
                ARN=resource.get('ARN'),
                accountId=resource.get('accountId'),
                type=resource.get('type')
            )
            for resource in resources
        ]
    except Exception as e:
        logger.warning(f"Failed to create Resources: {e}")
        return []

def convert_timestamp(timestamp_str):
    """Convert CloudTrail timestamp to proper datetime"""
    if not timestamp_str:
        return None
    
    try:
        # Parse ISO format: 2017-02-12T19:57:06Z
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except Exception as e:
        logger.warning(f"Could not parse timestamp '{timestamp_str}': {e}")
        return None

def main():
    """Main function to create CloudTrail DuckDB database"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Create DuckDB database from CloudTrail logs")
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing CloudTrail JSON.gz files"
    )
    parser.add_argument(
        "--output-db",
        type=Path,
        required=True,
        help="Output DuckDB database file path"
    )
    
    args = parser.parse_args()
    
    # Use provided paths
    data_dir = args.input_dir
    output_db = args.output_db
    
    # Create output directory if it doesn't exist
    output_db.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove existing database
    if output_db.exists():
        output_db.unlink()
        logger.info(f"Removed existing database: {output_db}")
    
    # Create new database
    logger.info(f"Creating new CloudTrail database: {output_db}")
    
    with duckdb.connect(str(output_db)) as conn:
        # Create table
        create_cloudtrail_table(conn)
        
        # Process all CloudTrail files
        total_records = 0
        cloudtrail_files = sorted(data_dir.glob("flaws_cloudtrail*.json.gz"))
        
        logger.info(f"Processing {len(cloudtrail_files)} CloudTrail files...")
        
        for file_path in cloudtrail_files:
            records_inserted = process_cloudtrail_file(conn, file_path)
            total_records += records_inserted
        
        # Get database statistics
        logger.info("Database Creation Summary:")
        logger.info(f"Total records inserted: {total_records:,}")
        
        # Show date range
        result = conn.execute("""
            SELECT 
                MIN(eventtime) as earliest_event,
                MAX(eventtime) as latest_event,
                COUNT(*) as total_records
            FROM cloudtrail_logs
            WHERE eventtime IS NOT NULL
        """).fetchone()
        
        if result:
            earliest, latest, count = result
            logger.info(f"Date range: {earliest} to {latest}")
            logger.info(f"Records with valid timestamps: {count:,}")
        
        # Show top event types
        logger.info("Top Event Types:")
        top_events = conn.execute("""
            SELECT eventname, COUNT(*) as count
            FROM cloudtrail_logs
            GROUP BY eventname
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        
        for event_name, count in top_events:
            logger.info(f"{event_name}: {count:,}")
    
    logger.info(f"CloudTrail master database created successfully: {output_db}")
    logger.info("Ready for partitioning into 2-3 month chunks")

if __name__ == "__main__":
    main()