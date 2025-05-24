#!/usr/bin/env python3
"""
Example agent workflow using the CloudTrail analysis tools.
This demonstrates how the security agent will interact with the tools to answer questions.
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cloud_logs_security_agent.tools.duckdb_logs import create_cloudtrail_analyzer
import json

class SimpleSecurityAgent:
    """
    A simple security agent that demonstrates how to use the CloudTrail tools
    to answer natural language security questions.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.analyzer = None
    
    def __enter__(self):
        self.analyzer = create_cloudtrail_analyzer(self.db_path)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.analyzer:
            self.analyzer.close()
    
    def answer_question(self, question: str) -> str:
        """
        Answer a security-related question using CloudTrail analysis.
        This is a simplified version of what the trained RL agent will do.
        """
        
        question_lower = question.lower()
        
        # Pattern matching for different types of questions
        if "login" in question_lower or "signin" in question_lower:
            return self._analyze_authentication_events(question)
        
        elif "failed" in question_lower or "error" in question_lower:
            return self._analyze_failed_operations(question)
        
        elif "delete" in question_lower or "terminate" in question_lower:
            return self._analyze_destructive_operations(question)
        
        elif "user" in question_lower and ("activity" in question_lower or "what did" in question_lower):
            return self._analyze_user_activity(question)
        
        elif "unusual" in question_lower or "suspicious" in question_lower or "anomaly" in question_lower:
            return self._detect_anomalies(question)
        
        elif "ip" in question_lower or "address" in question_lower:
            return self._analyze_ip_activity(question)
        
        else:
            # Generic search
            return self._generic_search(question)
    
    def _analyze_authentication_events(self, question: str) -> str:
        """Analyze authentication-related events."""
        
        # Search for authentication events
        auth_events = self.analyzer.search_logs(
            query="",
            event_names=["ConsoleLogin", "AssumeRole", "GetSessionToken", "SamlResponse"],
            limit=20
        )
        
        if not auth_events:
            return "No authentication events found in the CloudTrail logs."
        
        # Analyze the results
        successful_logins = [e for e in auth_events if not e['errorCode']]
        failed_logins = [e for e in auth_events if e['errorCode']]
        
        # Get unique IPs
        login_ips = set(e['sourceIPAddress'] for e in auth_events if e['sourceIPAddress'])
        
        response = f"Authentication Analysis:\n"
        response += f"• Total authentication events: {len(auth_events)}\n"
        response += f"• Successful: {len(successful_logins)}\n"
        response += f"• Failed: {len(failed_logins)}\n"
        response += f"• Unique source IPs: {len(login_ips)}\n"
        
        if failed_logins:
            response += f"\nRecent failed authentication attempts:\n"
            for event in failed_logins[:5]:
                response += f"• {event['eventTime']}: {event['eventName']} from {event['sourceIPAddress']} - {event['errorCode']}\n"
        
        if successful_logins:
            response += f"\nRecent successful logins:\n"
            for event in successful_logins[:3]:
                response += f"• {event['eventTime']}: {event['eventName']} from {event['sourceIPAddress']}\n"
        
        return response
    
    def _analyze_failed_operations(self, question: str) -> str:
        """Analyze failed operations and errors."""
        
        # Search for events with errors
        error_events = self.analyzer.search_logs(
            query="",
            error_codes=["AccessDenied", "UnauthorizedOperation", "InvalidUserID.NotFound", "Forbidden"],
            limit=50
        )
        
        if not error_events:
            return "No failed operations found in the recent CloudTrail logs."
        
        # Analyze error patterns
        error_counts = {}
        ip_errors = {}
        event_errors = {}
        
        for event in error_events:
            error_code = event['errorCode']
            error_counts[error_code] = error_counts.get(error_code, 0) + 1
            
            ip = event['sourceIPAddress']
            if ip:
                ip_errors[ip] = ip_errors.get(ip, 0) + 1
            
            event_name = event['eventName']
            event_errors[event_name] = event_errors.get(event_name, 0) + 1
        
        response = f"Failed Operations Analysis:\n"
        response += f"• Total failed operations: {len(error_events)}\n"
        
        # Top error types
        top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        response += f"\nTop error types:\n"
        for error, count in top_errors:
            response += f"• {error}: {count} occurrences\n"
        
        # Top IPs with errors
        top_error_ips = sorted(ip_errors.items(), key=lambda x: x[1], reverse=True)[:5]
        response += f"\nTop source IPs with errors:\n"
        for ip, count in top_error_ips:
            response += f"• {ip}: {count} failed operations\n"
        
        # Recent failures
        response += f"\nRecent failed operations:\n"
        for event in error_events[:5]:
            response += f"• {event['eventTime']}: {event['eventName']} - {event['errorCode']} from {event['sourceIPAddress']}\n"
        
        return response
    
    def _analyze_destructive_operations(self, question: str) -> str:
        """Analyze potentially destructive operations."""
        
        # Search for destructive operations
        destructive_events = self.analyzer.search_logs(
            query="",
            event_names=["TerminateInstances", "DeleteBucket", "DeleteDBInstance", "DeleteStack", 
                        "DeleteFunction", "DeleteUser", "DeleteRole", "DeregisterImage"],
            limit=20
        )
        
        if not destructive_events:
            # Try broader search
            destructive_events = self.analyzer.search_logs(query="Delete", limit=20)
        
        if not destructive_events:
            return "No destructive operations found in the CloudTrail logs."
        
        # Analyze results
        successful_deletions = [e for e in destructive_events if not e['errorCode']]
        failed_deletions = [e for e in destructive_events if e['errorCode']]
        
        response = f"Destructive Operations Analysis:\n"
        response += f"• Total destructive operations attempted: {len(destructive_events)}\n"
        response += f"• Successful: {len(successful_deletions)}\n"
        response += f"• Failed: {len(failed_deletions)}\n"
        
        if successful_deletions:
            response += f"\n🚨 Successful destructive operations:\n"
            for event in successful_deletions[:5]:
                response += f"• {event['eventTime']}: {event['eventName']} from {event['sourceIPAddress']}\n"
        
        if failed_deletions:
            response += f"\nFailed destructive operations:\n"
            for event in failed_deletions[:3]:
                response += f"• {event['eventTime']}: {event['eventName']} - {event['errorCode']} from {event['sourceIPAddress']}\n"
        
        return response
    
    def _analyze_user_activity(self, question: str) -> str:
        """Analyze activity for a specific user."""
        
        # Try to extract username from question
        words = question.split()
        potential_users = [word for word in words if word not in ['user', 'activity', 'what', 'did', 'the', 'a', 'an']]
        
        if not potential_users:
            return "Please specify a username to analyze. Example: 'What did user john.doe do?'"
        
        user = potential_users[0]
        analysis = self.analyzer.analyze_user_activity(user, limit=50)
        
        if analysis['total_events'] == 0:
            return f"No activity found for user '{user}' in the CloudTrail logs."
        
        response = f"User Activity Analysis for '{user}':\n"
        response += f"• Total events: {analysis['total_events']}\n"
        response += f"• Time range: {analysis['time_range']['earliest']} to {analysis['time_range']['latest']}\n"
        response += f"• AWS services used: {len(analysis['aws_services'])}\n"
        response += f"• Regions accessed: {len(analysis['regions'])}\n"
        response += f"• Source IPs: {len(analysis['source_ips'])}\n"
        
        # Top activities
        top_activities = list(analysis['event_types'].items())[:5]
        response += f"\nTop activities:\n"
        for activity, count in top_activities:
            response += f"• {activity}: {count} times\n"
        
        # Errors
        if analysis['errors']:
            response += f"\nErrors encountered: {len(analysis['errors'])}\n"
            for error in analysis['errors'][:3]:
                response += f"• {error['eventTime']}: {error['eventName']} - {error['errorCode']}\n"
        
        # High-risk activities
        if analysis['high_risk_activities']:
            response += f"\n🚨 High-risk activities: {len(analysis['high_risk_activities'])}\n"
            for activity in analysis['high_risk_activities'][:3]:
                response += f"• {activity['eventTime']}: {activity['eventName']} from {activity['sourceIP']}\n"
        
        return response
    
    def _detect_anomalies(self, question: str) -> str:
        """Detect security anomalies."""
        
        anomalies = self.analyzer.detect_anomalies(time_window_hours=24*7)  # 1 week
        
        if anomalies['total_events'] == 0:
            return "Insufficient data for anomaly detection."
        
        response = f"Security Anomaly Detection ({anomalies['analysis_period']}):\n"
        response += f"• Total events analyzed: {anomalies['total_events']}\n"
        
        # Unusual IPs
        unusual_ips = anomalies['anomalies']['unusual_ips']
        if unusual_ips:
            response += f"\n🌐 Unusual IP addresses ({len(unusual_ips)}):\n"
            for ip_info in unusual_ips[:5]:
                response += f"• {ip_info['sourceIP']}: {ip_info['event_count']} events ({ip_info['percentage']}%)\n"
        
        # Error spikes
        error_spikes = anomalies['anomalies']['error_spikes']
        if error_spikes:
            response += f"\n❌ Error spikes ({len(error_spikes)}):\n"
            for error_info in error_spikes[:3]:
                response += f"• {error_info['errorCode']}: {error_info['occurrences']} occurrences\n"
        
        # Off-hours activity
        off_hours = anomalies['anomalies']['off_hours_activity']
        if off_hours:
            response += f"\n🌙 Off-hours activity ({len(off_hours)} events):\n"
            for activity in off_hours[:3]:
                response += f"• {activity['eventTime']}: {activity['eventName']} from {activity['sourceIP']}\n"
        
        # Privilege changes
        privilege_changes = anomalies['anomalies']['privilege_changes']
        if privilege_changes:
            response += f"\n⚠️  Privilege changes ({len(privilege_changes)}):\n"
            for change in privilege_changes[:3]:
                status = "✅" if change['success'] else "❌"
                response += f"• {change['eventTime']}: {change['eventName']} {status} from {change['sourceIP']}\n"
        
        return response
    
    def _analyze_ip_activity(self, question: str) -> str:
        """Analyze IP address activity."""
        
        # Get recent events and analyze IP patterns
        recent_events = self.analyzer.search_logs(query="", limit=500)
        
        if not recent_events:
            return "No recent events found for IP analysis."
        
        ip_analysis = {}
        for event in recent_events:
            ip = event['sourceIPAddress']
            if ip:
                if ip not in ip_analysis:
                    ip_analysis[ip] = {
                        'count': 0,
                        'events': set(),
                        'services': set(),
                        'errors': 0,
                        'latest': event['eventTime']
                    }
                
                ip_analysis[ip]['count'] += 1
                ip_analysis[ip]['events'].add(event['eventName'])
                ip_analysis[ip]['services'].add(event['eventSource'])
                if event['errorCode']:
                    ip_analysis[ip]['errors'] += 1
        
        # Sort by activity level
        sorted_ips = sorted(ip_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
        
        response = f"IP Address Activity Analysis:\n"
        response += f"• Total unique IPs: {len(sorted_ips)}\n"
        response += f"• Events analyzed: {len(recent_events)}\n"
        
        response += f"\nTop active IP addresses:\n"
        for ip, data in sorted_ips[:10]:
            error_rate = (data['errors'] / data['count'] * 100) if data['count'] > 0 else 0
            response += f"• {ip}: {data['count']} events, {len(data['services'])} services, {error_rate:.1f}% errors\n"
        
        return response
    
    def _generic_search(self, question: str) -> str:
        """Perform a generic search based on the question."""
        
        # Extract potential search terms from the question
        search_terms = [word for word in question.split() if len(word) > 3 and word.lower() not in 
                       ['what', 'when', 'where', 'who', 'how', 'did', 'the', 'was', 'were', 'are', 'is']]
        
        if not search_terms:
            return "Please provide more specific search terms in your question."
        
        # Use the first few search terms
        search_query = " ".join(search_terms[:3])
        
        results = self.analyzer.search_logs(query=search_query, limit=10)
        
        if not results:
            return f"No events found matching your search for '{search_query}'."
        
        response = f"Search Results for '{search_query}':\n"
        response += f"• Found {len(results)} matching events\n\n"
        
        for event in results[:5]:
            status = "✅" if not event['errorCode'] else f"❌ {event['errorCode']}"
            response += f"• {event['eventTime']}: {event['eventName']} {status}\n"
            response += f"  Source: {event['eventSource']} | IP: {event['sourceIPAddress']}\n\n"
        
        return response

def main():
    """Demonstrate the security agent answering various questions."""
    
    db_path = "data/flaws_cloudtrail_logs_simple-schema.duckdb"
    
    # Example security questions
    questions = [
        "Show me recent login attempts",
        "What failed operations happened recently?",
        "Find any destructive operations like deletions",
        "Detect any suspicious or unusual activity",
        "What activity did user admin have?",
        "Analyze IP address patterns",
        "Show me EC2 related events"
    ]
    
    print("🤖 Simple Security Agent Demo")
    print("=" * 50)
    
    try:
        with SimpleSecurityAgent(db_path) as agent:
            for i, question in enumerate(questions, 1):
                print(f"\n❓ Question {i}: {question}")
                print("🔍 " + "-" * 40)
                
                answer = agent.answer_question(question)
                print(answer)
                
                print("\n" + "="*50)
        
        print("\n✅ Demo completed! This shows how the trained RL agent will use the CloudTrail tools.")
    
    except FileNotFoundError:
        print("❌ Database file not found. Please run the setup script first:")
        print("   python setup_cloudtrail_db_simple.py")
    except Exception as e:
        print(f"❌ Demo failed: {e}")

if __name__ == "__main__":
    main()
