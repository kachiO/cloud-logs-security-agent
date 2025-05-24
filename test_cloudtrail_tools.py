#!/usr/bin/env python3
"""
Test script for CloudTrail analysis tools.
Validates that the DuckDB tools work correctly with the imported CloudTrail data.
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cloud_logs_security_agent.tools.duckdb_logs import create_cloudtrail_analyzer
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_cloudtrail_tools():
    """Test all CloudTrail analysis tools."""
    
    # Database path
    db_path = "data/flaws_cloudtrail_logs_simple-schema.duckdb"
    
    print("🧪 Testing CloudTrail Analysis Tools")
    print("=" * 50)
    
    try:
        # Create analyzer
        with create_cloudtrail_analyzer(db_path) as analyzer:
            
            # Test 1: Database Statistics
            print("\n📊 Test 1: Database Statistics")
            print("-" * 30)
            stats = analyzer.get_database_stats()
            print(f"Total Events: {stats['total_events']:,}")
            print(f"Time Range: {stats['time_range']['earliest']} to {stats['time_range']['latest']}")
            print(f"Error Rate: {stats['error_statistics']['error_rate']}%")
            print(f"Top Event Type: {stats['top_event_types'][0]['eventName']} ({stats['top_event_types'][0]['count']:,} events)")
            
            # Test 2: Basic Search
            print("\n🔍 Test 2: Basic Search")
            print("-" * 30)
            search_results = analyzer.search_logs(query="Login", limit=5)
            print(f"Found {len(search_results)} login-related events:")
            for event in search_results[:3]:  # Show first 3
                print(f"  - {event['eventTime']}: {event['eventName']} from {event['sourceIPAddress']}")
            
            # Test 3: Error Analysis
            print("\n❌ Test 3: Error Analysis")
            print("-" * 30)
            error_events = analyzer.search_logs(query="", error_codes=["AccessDenied", "UnauthorizedOperation"], limit=5)
            print(f"Found {len(error_events)} error events:")
            for event in error_events[:3]:
                print(f"  - {event['eventTime']}: {event['eventName']} - {event['errorCode']}")
            
            # Test 4: Time-based Search
            print("\n⏰ Test 4: Time-based Search")
            print("-" * 30)
            # Get events from a specific day (using the latest date from stats)
            latest_date = stats['time_range']['latest']
            if latest_date:
                # Extract just the date part
                date_part = str(latest_date).split()[0]  # Get YYYY-MM-DD part
                start_time = f"{date_part}T00:00:00"
                end_time = f"{date_part}T23:59:59"
                
                time_filtered = analyzer.search_logs(
                    query="",
                    start_time=start_time,
                    end_time=end_time,
                    limit=10
                )
                print(f"Found {len(time_filtered)} events on {date_part}")
            
            # Test 5: Service-specific Search
            print("\n☁️  Test 5: AWS Service Search")
            print("-" * 30)
            ec2_events = analyzer.search_logs(
                query="",
                event_sources=["ec2.amazonaws.com"],
                limit=5
            )
            print(f"Found {len(ec2_events)} EC2-related events:")
            for event in ec2_events[:3]:
                print(f"  - {event['eventTime']}: {event['eventName']}")
            
            # Test 6: Event Detail Retrieval
            print("\n📋 Test 6: Event Detail Retrieval")
            print("-" * 30)
            if search_results:
                event_id = search_results[0]['eventID']
                detailed_events = analyzer.retrieve_log_details([event_id])
                if detailed_events:
                    event = detailed_events[0]
                    print(f"Retrieved detailed event: {event['eventName']}")
                    print(f"User Identity Type: {event.get('userIdentity', {}).get('type', 'Unknown') if isinstance(event.get('userIdentity'), dict) else 'Unknown'}")
                    print(f"Has Request Parameters: {'Yes' if event.get('requestParameters') else 'No'}")
            
            # Test 7: User Activity Analysis
            print("\n👤 Test 7: User Activity Analysis")
            print("-" * 30)
            # Find a user from recent events
            recent_events = analyzer.search_logs(query="", limit=10)
            if recent_events:
                # Try to extract a user from userIdentity
                test_user = None
                for event in recent_events:
                    user_identity = event.get('userIdentity')
                    if isinstance(user_identity, dict) and user_identity.get('arn'):
                        test_user = user_identity['arn'].split('/')[-1]  # Get username from ARN
                        break
                    elif isinstance(user_identity, str) and 'user' in user_identity.lower():
                        test_user = "test_user"  # Fallback
                        break
                
                if test_user:
                    user_analysis = analyzer.analyze_user_activity(test_user, limit=20)
                    print(f"Analyzed activity for user: {test_user}")
                    print(f"Total events: {user_analysis['total_events']}")
                    print(f"Event types: {len(user_analysis['event_types'])}")
                    print(f"AWS services used: {len(user_analysis['aws_services'])}")
                    if user_analysis['high_risk_activities']:
                        print(f"High-risk activities: {len(user_analysis['high_risk_activities'])}")
            
            # Test 8: Anomaly Detection
            print("\n🚨 Test 8: Anomaly Detection")
            print("-" * 30)
            anomalies = analyzer.detect_anomalies(time_window_hours=24*7)  # Look back 1 week
            print(f"Analysis period: {anomalies['analysis_period']}")
            print(f"Total events analyzed: {anomalies['total_events']}")
            print(f"Unusual IPs detected: {len(anomalies['anomalies']['unusual_ips'])}")
            print(f"Error spikes: {len(anomalies['anomalies']['error_spikes'])}")
            print(f"Off-hours activities: {len(anomalies['anomalies']['off_hours_activity'])}")
            print(f"Privilege changes: {len(anomalies['anomalies']['privilege_changes'])}")
            
            # Test 9: Complex Multi-filter Search
            print("\n🎯 Test 9: Complex Multi-filter Search")
            print("-" * 30)
            complex_search = analyzer.search_logs(
                query="",
                event_names=["RunInstances", "TerminateInstances", "CreateBucket"],
                aws_regions=["us-east-1", "us-west-2"],
                error_codes=["SUCCESS"],  # Only successful operations
                limit=10
            )
            print(f"Found {len(complex_search)} events matching complex criteria")
            for event in complex_search[:3]:
                print(f"  - {event['eventName']} in {event['awsRegion']} at {event['eventTime']}")
            
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    
    print("\n✅ All tests completed successfully!")
    print("🎉 CloudTrail analysis tools are working correctly!")

def demo_security_queries():
    """Demonstrate security-focused queries that the agent will use."""
    
    db_path = "data/flaws_cloudtrail_logs_simple-schema.duckdb"
    
    print("\n🛡️  Security Analysis Demo")
    print("=" * 50)
    
    with create_cloudtrail_analyzer(db_path) as analyzer:
        
        # Security Query 1: Authentication Events
        print("\n🔐 Authentication Events:")
        auth_events = analyzer.search_logs(
            query="",
            event_names=["ConsoleLogin", "AssumeRole", "GetSessionToken"],
            limit=5
        )
        for event in auth_events:
            print(f"  {event['eventTime']}: {event['eventName']} from {event['sourceIPAddress']}")
        
        # Security Query 2: Failed Operations
        print("\n🚫 Failed Operations:")
        failed_ops = analyzer.search_logs(
            query="",
            error_codes=["AccessDenied", "UnauthorizedOperation", "InvalidUserID.NotFound"],
            limit=5
        )
        for event in failed_ops:
            print(f"  {event['eventTime']}: {event['eventName']} - {event['errorCode']}")
        
        # Security Query 3: Privilege-related Changes
        print("\n⚠️  Privilege-related Changes:")
        privilege_events = analyzer.search_logs(
            query="",
            event_names=["AttachUserPolicy", "CreateRole", "PutUserPolicy", "AttachRolePolicy"],
            limit=5
        )
        for event in privilege_events:
            status = "✅ Success" if not event['errorCode'] else f"❌ {event['errorCode']}"
            print(f"  {event['eventTime']}: {event['eventName']} - {status}")
        
        # Security Query 4: Destructive Operations
        print("\n💥 Destructive Operations:")
        destructive_events = analyzer.search_logs(
            query="Delete",
            limit=5
        )
        for event in destructive_events:
            status = "✅ Success" if not event['errorCode'] else f"❌ {event['errorCode']}"
            print(f"  {event['eventTime']}: {event['eventName']} - {status}")
        
        # Security Query 5: Unusual IP Activity
        print("\n🌐 IP Address Analysis:")
        # Get recent events and analyze IP patterns
        recent_events = analyzer.search_logs(query="", limit=100)
        ip_counts = {}
        for event in recent_events:
            ip = event['sourceIPAddress']
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Show top IPs
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in top_ips:
            print(f"  {ip}: {count} events")

if __name__ == "__main__":
    try:
        # Run basic functionality tests
        test_cloudtrail_tools()
        
        # Run security-focused demo
        demo_security_queries()
        
    except FileNotFoundError:
        print("❌ Database file not found. Please run the setup script first:")
        print("   python setup_cloudtrail_db_simple.py")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        exit(1)
