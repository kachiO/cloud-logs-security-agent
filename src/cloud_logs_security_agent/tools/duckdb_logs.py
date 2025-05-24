"""
DuckDB-based tools for CloudTrail log analysis.
These tools provide the agent with the ability to search and retrieve CloudTrail events.
"""

import duckdb
import json
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class CloudTrailAnalyzer:
    """
    Main class for analyzing CloudTrail logs using DuckDB.
    Provides search, retrieval, and analysis capabilities for the security agent.
    """
    
    def __init__(self, db_path: str | Path):
        """Initialize connection to CloudTrail database."""
        self.db_path = Path(db_path)
        self.conn = None
        self._connect()
    
    def _connect(self):
        """Establish connection to DuckDB database."""
        try:
            self.conn = duckdb.connect(str(self.db_path))
            logger.info(f"Connected to CloudTrail database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to database {self.db_path}: {e}")
            raise
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def search_logs(
        self,
        query: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        event_names: Optional[List[str]] = None,
        event_sources: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        error_codes: Optional[List[str]] = None,
        aws_regions: Optional[List[str]] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Search CloudTrail logs with flexible filtering options.
        
        Args:
            query: Free-text search across event names, sources, and user identities
            start_time: Start time filter (ISO format: '2023-01-01T00:00:00')
            end_time: End time filter (ISO format: '2023-01-01T23:59:59')
            event_names: List of specific event names to filter by
            event_sources: List of AWS services to filter by
            source_ips: List of source IP addresses to filter by
            error_codes: List of error codes to filter by (None for successful events)
            aws_regions: List of AWS regions to filter by
            limit: Maximum number of results to return
            
        Returns:
            List of matching CloudTrail events with key fields
        """
        
        # Build the WHERE clause dynamically
        where_clauses = []
        params = []
        
        # Free-text search across multiple fields
        if query:
            search_clause = """(
                LOWER(eventName) LIKE LOWER(?) OR 
                LOWER(eventSource) LIKE LOWER(?) OR 
                LOWER(userIdentity) LIKE LOWER(?) OR
                LOWER(sourceIPAddress) LIKE LOWER(?)
            )"""
            where_clauses.append(search_clause)
            search_term = f"%{query}%"
            params.extend([search_term, search_term, search_term, search_term])
        
        # Time range filtering
        if start_time:
            where_clauses.append("eventTime >= ?")
            params.append(start_time)
        
        if end_time:
            where_clauses.append("eventTime <= ?")
            params.append(end_time)
        
        # Specific event name filtering
        if event_names:
            placeholders = ",".join("?" * len(event_names))
            where_clauses.append(f"eventName IN ({placeholders})")
            params.extend(event_names)
        
        # AWS service filtering
        if event_sources:
            placeholders = ",".join("?" * len(event_sources))
            where_clauses.append(f"eventSource IN ({placeholders})")
            params.extend(event_sources)
        
        # Source IP filtering
        if source_ips:
            ip_clauses = []
            for ip in source_ips:
                if '*' in ip or '%' in ip:
                    ip_clauses.append("sourceIPAddress LIKE ?")
                    params.append(ip.replace('*', '%'))
                else:
                    ip_clauses.append("sourceIPAddress = ?")
                    params.append(ip)
            where_clauses.append(f"({' OR '.join(ip_clauses)})")
        
        # Error code filtering
        if error_codes:
            if 'SUCCESS' in error_codes:
                # Include both NULL (success) and specific error codes
                other_codes = [code for code in error_codes if code != 'SUCCESS']
                if other_codes:
                    placeholders = ",".join("?" * len(other_codes))
                    where_clauses.append(f"(errorCode IS NULL OR errorCode IN ({placeholders}))")
                    params.extend(other_codes)
                else:
                    where_clauses.append("errorCode IS NULL")
            else:
                placeholders = ",".join("?" * len(error_codes))
                where_clauses.append(f"errorCode IN ({placeholders})")
                params.extend(error_codes)
        
        # AWS region filtering
        if aws_regions:
            placeholders = ",".join("?" * len(aws_regions))
            where_clauses.append(f"awsRegion IN ({placeholders})")
            params.extend(aws_regions)
        
        # Build the complete query
        base_query = """
        SELECT 
            eventID,
            eventTime,
            eventName,
            eventSource,
            sourceIPAddress,
            userIdentity,
            awsRegion,
            errorCode,
            errorMessage,
            requestParameters,
            responseElements
        FROM cloudtrail_events
        """
        
        if where_clauses:
            base_query += " WHERE " + " AND ".join(where_clauses)
        
        base_query += " ORDER BY eventTime DESC LIMIT ?"
        params.append(limit)
        
        try:
            results = self.conn.execute(base_query, params).fetchall()
            
            # Convert to list of dictionaries
            columns = ['eventID', 'eventTime', 'eventName', 'eventSource', 'sourceIPAddress', 
                      'userIdentity', 'awsRegion', 'errorCode', 'errorMessage', 
                      'requestParameters', 'responseElements']
            
            events = []
            for row in results:
                event = dict(zip(columns, row))
                # Parse JSON fields if they're strings
                for json_field in ['userIdentity', 'requestParameters', 'responseElements']:
                    if event[json_field] and isinstance(event[json_field], str):
                        try:
                            event[json_field] = json.loads(event[json_field])
                        except json.JSONDecodeError:
                            pass  # Keep as string if not valid JSON
                events.append(event)
            
            logger.info(f"Found {len(events)} events matching search criteria")
            return events
            
        except Exception as e:
            logger.error(f"Search query failed: {e}")
            raise

    def retrieve_log_details(self, event_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieve complete details for specific CloudTrail events.
        
        Args:
            event_ids: List of CloudTrail event IDs to retrieve
            
        Returns:
            List of complete CloudTrail event records
        """
        
        if not event_ids:
            return []
        
        # Build query with placeholders
        placeholders = ",".join("?" * len(event_ids))
        query = f"""
        SELECT *
        FROM cloudtrail_events
        WHERE eventID IN ({placeholders})
        ORDER BY eventTime DESC
        """
        
        try:
            results = self.conn.execute(query, event_ids).fetchall()
            
            # Get column names
            columns = [desc[0] for desc in self.conn.description]
            
            # Convert to list of dictionaries
            events = []
            for row in results:
                event = dict(zip(columns, row))
                
                # Parse JSON fields
                json_fields = ['userIdentity', 'requestParameters', 'responseElements', 'resources', 
                              'additionalEventData', 'serviceEventDetails']
                
                for field in json_fields:
                    if event.get(field) and isinstance(event[field], str):
                        try:
                            event[field] = json.loads(event[field])
                        except json.JSONDecodeError:
                            pass  # Keep as string if not valid JSON
                
                events.append(event)
            
            logger.info(f"Retrieved {len(events)} detailed event records")
            return events
            
        except Exception as e:
            logger.error(f"Failed to retrieve event details: {e}")
            raise

    def analyze_user_activity(
        self, 
        user_identifier: str,
        start_time: Optional[str] = None, 
        end_time: Optional[str] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Analyze activity for a specific user or role.
        
        Args:
            user_identifier: Username, ARN, or principal ID to analyze
            start_time: Start time for analysis
            end_time: End time for analysis
            limit: Maximum events to analyze
            
        Returns:
            Dictionary with user activity analysis
        """
        
        # Search for events related to this user
        events = self.search_logs(
            query=user_identifier,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )
        
        if not events:
            return {
                'user_identifier': user_identifier,
                'total_events': 0,
                'analysis': 'No events found for this user'
            }
        
        # Analyze the events
        analysis = {
            'user_identifier': user_identifier,
            'total_events': len(events),
            'time_range': {
                'earliest': min(event['eventTime'] for event in events),
                'latest': max(event['eventTime'] for event in events)
            },
            'event_types': {},
            'aws_services': {},
            'regions': {},
            'source_ips': set(),
            'errors': [],
            'high_risk_activities': []
        }
        
        # High-risk event patterns
        high_risk_patterns = [
            'Delete', 'Terminate', 'Destroy', 'Remove',
            'Policy', 'Role', 'User', 'Group',
            'Password', 'Key', 'Secret', 'Token'
        ]
        
        for event in events:
            # Count event types
            event_name = event['eventName']
            analysis['event_types'][event_name] = analysis['event_types'].get(event_name, 0) + 1
            
            # Count AWS services
            service = event['eventSource']
            analysis['aws_services'][service] = analysis['aws_services'].get(service, 0) + 1
            
            # Count regions
            region = event['awsRegion']
            if region:
                analysis['regions'][region] = analysis['regions'].get(region, 0) + 1
            
            # Collect source IPs
            if event['sourceIPAddress']:
                analysis['source_ips'].add(event['sourceIPAddress'])
            
            # Collect errors
            if event['errorCode']:
                analysis['errors'].append({
                    'eventTime': event['eventTime'],
                    'eventName': event_name,
                    'errorCode': event['errorCode'],
                    'errorMessage': event['errorMessage']
                })
            
            # Check for high-risk activities
            if any(pattern.lower() in event_name.lower() for pattern in high_risk_patterns):
                analysis['high_risk_activities'].append({
                    'eventTime': event['eventTime'],
                    'eventName': event_name,
                    'eventSource': service,
                    'sourceIP': event['sourceIPAddress']
                })
        
        # Convert sets to lists for JSON serialization
        analysis['source_ips'] = list(analysis['source_ips'])
        
        # Sort by frequency
        analysis['event_types'] = dict(sorted(analysis['event_types'].items(), key=lambda x: x[1], reverse=True))
        analysis['aws_services'] = dict(sorted(analysis['aws_services'].items(), key=lambda x: x[1], reverse=True))
        analysis['regions'] = dict(sorted(analysis['regions'].items(), key=lambda x: x[1], reverse=True))
        
        return analysis

    def detect_anomalies(
        self,
        time_window_hours: int = 24,
        min_events_threshold: int = 100
    ) -> Dict[str, Any]:
        """
        Detect potential security anomalies in recent CloudTrail events.
        
        Args:
            time_window_hours: Hours to look back for anomaly detection
            min_events_threshold: Minimum events needed for analysis
            
        Returns:
            Dictionary with detected anomalies
        """
        
        # Calculate time window
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        # Get recent events
        recent_events = self.search_logs(
            query="",  # Get all events
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            limit=1000
        )
        
        if len(recent_events) < min_events_threshold:
            return {
                'analysis_period': f"{time_window_hours} hours",
                'total_events': len(recent_events),
                'message': f'Insufficient events ({len(recent_events)}) for anomaly detection'
            }
        
        anomalies = {
            'analysis_period': f"{time_window_hours} hours",
            'total_events': len(recent_events),
            'anomalies': {
                'unusual_ips': [],
                'error_spikes': [],
                'off_hours_activity': [],
                'privilege_changes': [],
                'destructive_operations': []
            }
        }
        
        # Track IP addresses and their frequency
        ip_counts = {}
        error_counts = {}
        
        for event in recent_events:
            # Track IP addresses
            source_ip = event['sourceIPAddress']
            if source_ip:
                ip_counts[source_ip] = ip_counts.get(source_ip, 0) + 1
            
            # Track errors
            if event['errorCode']:
                error_counts[event['errorCode']] = error_counts.get(event['errorCode'], 0) + 1
            
            # Check for off-hours activity (assuming business hours 9-17 UTC)
            event_time = datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
            if event_time.hour < 9 or event_time.hour > 17:
                anomalies['anomalies']['off_hours_activity'].append({
                    'eventTime': event['eventTime'],
                    'eventName': event['eventName'],
                    'sourceIP': source_ip,
                    'userIdentity': event.get('userIdentity', {}).get('type') if isinstance(event.get('userIdentity'), dict) else 'Unknown'
                })
            
            # Check for privilege-related changes
            privilege_events = ['AttachUserPolicy', 'DetachUserPolicy', 'CreateRole', 'DeleteRole', 
                               'AttachRolePolicy', 'DetachRolePolicy', 'CreateUser', 'DeleteUser']
            if event['eventName'] in privilege_events:
                anomalies['anomalies']['privilege_changes'].append({
                    'eventTime': event['eventTime'],
                    'eventName': event['eventName'],
                    'sourceIP': source_ip,
                    'success': event['errorCode'] is None
                })
            
            # Check for destructive operations
            destructive_events = ['DeleteBucket', 'TerminateInstances', 'DeleteDBInstance', 
                                'DeleteStack', 'DeleteFunction']
            if event['eventName'] in destructive_events:
                anomalies['anomalies']['destructive_operations'].append({
                    'eventTime': event['eventTime'],
                    'eventName': event['eventName'],
                    'sourceIP': source_ip,
                    'success': event['errorCode'] is None
                })
        
        # Identify unusual IP addresses (top 5% by frequency)
        if ip_counts:
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            threshold = max(10, len(sorted_ips) // 20)  # Top 5% or at least 10 events
            for ip, count in sorted_ips:
                if count >= threshold:
                    anomalies['anomalies']['unusual_ips'].append({
                        'sourceIP': ip,
                        'event_count': count,
                        'percentage': round(count / len(recent_events) * 100, 2)
                    })
        
        # Identify error spikes
        for error_code, count in error_counts.items():
            if count >= 5:  # Arbitrary threshold for error spike
                anomalies['anomalies']['error_spikes'].append({
                    'errorCode': error_code,
                    'occurrences': count,
                    'percentage': round(count / len(recent_events) * 100, 2)
                })
        
        # Limit results to prevent overwhelming output
        for category in anomalies['anomalies']:
            anomalies['anomalies'][category] = anomalies['anomalies'][category][:10]
        
        return anomalies

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the CloudTrail database.
        
        Returns:
            Dictionary with database statistics
        """
        
        stats = {}
        
        try:
            # Basic counts
            stats['total_events'] = self.conn.execute("SELECT COUNT(*) FROM cloudtrail_events").fetchone()[0]
            
            # Time range
            time_range = self.conn.execute("""
                SELECT MIN(eventTime) as earliest, MAX(eventTime) as latest 
                FROM cloudtrail_events
            """).fetchone()
            stats['time_range'] = {
                'earliest': time_range[0],
                'latest': time_range[1]
            }
            
            # Top event types
            event_types = self.conn.execute("""
                SELECT eventName, COUNT(*) as count 
                FROM cloudtrail_events 
                GROUP BY eventName 
                ORDER BY count DESC 
                LIMIT 10
            """).fetchall()
            stats['top_event_types'] = [{'eventName': name, 'count': count} for name, count in event_types]
            
            # Top AWS services
            services = self.conn.execute("""
                SELECT eventSource, COUNT(*) as count 
                FROM cloudtrail_events 
                GROUP BY eventSource 
                ORDER BY count DESC 
                LIMIT 10
            """).fetchall()
            stats['top_services'] = [{'eventSource': service, 'count': count} for service, count in services]
            
            # Error statistics
            error_stats = self.conn.execute("""
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(CASE WHEN errorCode IS NOT NULL THEN 1 END) as error_events,
                    COUNT(CASE WHEN errorCode IS NULL THEN 1 END) as success_events
                FROM cloudtrail_events
            """).fetchone()
            
            stats['error_statistics'] = {
                'total_events': error_stats[0],
                'error_events': error_stats[1],
                'success_events': error_stats[2],
                'error_rate': round(error_stats[1] / error_stats[0] * 100, 2) if error_stats[0] > 0 else 0
            }
            
            # Regions
            regions = self.conn.execute("""
                SELECT awsRegion, COUNT(*) as count 
                FROM cloudtrail_events 
                WHERE awsRegion IS NOT NULL 
                GROUP BY awsRegion 
                ORDER BY count DESC
            """).fetchall()
            stats['regions'] = [{'region': region, 'count': count} for region, count in regions]
            
            logger.info("Generated database statistics")
            return stats
            
        except Exception as e:
            logger.error(f"Failed to generate database statistics: {e}")
            raise


# Factory function for easy instantiation
def create_cloudtrail_analyzer(db_path: str | Path) -> CloudTrailAnalyzer:
    """
    Create a CloudTrail analyzer instance.
    
    Args:
        db_path: Path to the DuckDB CloudTrail database
        
    Returns:
        CloudTrailAnalyzer instance
    """
    return CloudTrailAnalyzer(db_path)
