"""CloudTrail Security Analysis Agent."""

import logging
from pathlib import Path

from mcp.client.stdio import StdioServerParameters, stdio_client
from strands import Agent
from strands.tools.mcp import MCPClient

logger = logging.getLogger(__name__)

# System prompt for CloudTrail security analysis
SYSTEM_PROMPT = """You are a CloudTrail Security Analysis Agent, specialized in investigating AWS CloudTrail logs for security incidents and anomalies.

Your primary capabilities:
- Query CloudTrail logs stored in DuckDB databases using SQL through the MCP query tool
- Analyze security events, failed authentication attempts, and suspicious activities
- Provide insights on access patterns, event frequencies, and potential threats
- Generate actionable security recommendations

Available MCP Tools:
- query: Execute SQL queries against DuckDB databases containing CloudTrail data

Database Schema Information:
The CloudTrail data is stored in a table called 'cloudtrail_events' with columns including:
- eventTime: Timestamp of the event
- eventName: Name of the AWS API call
- eventSource: AWS service that was called
- sourceIPAddress: IP address of the request
- userIdentity: Information about the user/role that made the request
- errorCode: Error code if the request failed
- errorMessage: Error message if the request failed
- resources: AWS resources involved in the event
- requestParameters: Parameters of the API call
- responseElements: Response elements from the API call

Guidelines:
1. Always use proper SQL syntax when querying the database
2. Use appropriate WHERE clauses to filter data by time ranges, event types, IP addresses, etc.
3. Focus on security-relevant events (authentication, authorization, access patterns)
4. Provide clear, actionable insights with specific evidence from the data
5. When analyzing failed events, investigate patterns and potential threats
6. Use efficient queries with LIMIT clauses to avoid overwhelming responses
7. Correlate events across different services and time periods when relevant
8. Always explain your SQL queries and their purpose

Example queries:
- Count total events: SELECT COUNT(*) FROM cloudtrail_events
- Find failed events: SELECT * FROM cloudtrail_events WHERE errorCode IS NOT NULL LIMIT 100
- Search by event type: SELECT * FROM cloudtrail_events WHERE eventName LIKE '%AssumeRole%' LIMIT 50
- Analyze IP patterns: SELECT sourceIPAddress, COUNT(*) as event_count FROM cloudtrail_events GROUP BY sourceIPAddress ORDER BY event_count DESC LIMIT 20

Remember: CloudTrail logs contain sensitive security information. Always provide thorough analysis while being mindful of the security implications of your findings."""


def create_motherduck_client(db_path: str = None) -> MCPClient:
    """Create MotherDuck MCP client for local DuckDB"""
    args = ["mcp-server-motherduck"]
    
    if db_path:
        args.extend(["--db-path", db_path])
        args.append("--read-only")
    else:
        args.extend(["--db-path", ":memory:"])
    
    return MCPClient(
        lambda: stdio_client(
            StdioServerParameters(command="uvx", args=args)
        )
    )


class CloudTrailAgent:
    """CloudTrail Security Analysis Agent."""
    
    def __init__(
        self, 
        model: str = "anthropic/claude-3-7-sonnet-20250219",
        db_path: str = None
    ):
        """Initialize the CloudTrail agent.
        
        Args:
            model: Model to use for the agent
            db_path: Path to DuckDB file (optional, defaults to memory)
        """
        self.db_path = db_path
        self.mcp_client = create_motherduck_client(db_path)
        
        self.agent = Agent(
            model=model,
            system_prompt=SYSTEM_PROMPT,
            tools=[self.mcp_client]
        )
    
    def analyze(self, query: str) -> str:
        """Analyze CloudTrail logs based on the given query.
        
        Args:
            query: Security analysis query
            
        Returns:
            Analysis results and insights
        """
        try:
            result = self.agent(query)
            return result.message
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return f"Analysis failed: {str(e)}"
    
    async def analyze_async(self, query: str) -> str:
        """Async version of analyze method.
        
        Args:
            query: Security analysis query
            
        Returns:
            Analysis results and insights
        """
        try:
            result = await self.agent.invoke_async(query)
            return result.message
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return f"Analysis failed: {str(e)}"
    
    def get_partitions(self) -> list:
        """Get available DuckDB partition files.
        
        Returns:
            List of available partition names
        """
        try:
            partitions_path = Path("data/flaws_cloudtrail_duckdb/partitions")
            if not partitions_path.exists():
                return []
            
            partition_files = list(partitions_path.glob("*.duckdb"))
            partitions = [f.stem for f in partition_files]
            return sorted(partitions)
        except Exception as e:
            logger.error(f"Failed to get partitions: {e}")
            return []


def create_cloudtrail_agent(
    model: str = "anthropic/claude-3-7-sonnet-20250219",
    db_path: str = None
) -> CloudTrailAgent:
    """Factory function to create a CloudTrail agent.
    
    Args:
        model: Model to use for the agent
        db_path: Path to DuckDB file (optional)
        
    Returns:
        Configured CloudTrail agent
    """
    return CloudTrailAgent(model=model, db_path=db_path)


# Example usage and testing
if __name__ == "__main__":
    # Example database path (adjust for your setup)
    db_path = "data/flaws_cloudtrail_duckdb/partitions/customer_201811_201901.duckdb"
    
    # Initialize agent with local DuckDB file
    agent = create_cloudtrail_agent(db_path=db_path)
    
    # Example analyses using SQL queries
    examples = [
        "Count the total number of CloudTrail events in the database",
        "Show me the database schema by describing the cloudtrail_events table",
        "What are the top 10 most common event types? Use a GROUP BY query",
        "Find failed authentication attempts where errorCode is not null",
        "Analyze IP address patterns - which IPs have the most activity?",
        "What security events should I be concerned about? Look for privilege escalation or suspicious patterns"
    ]
    
    print("CloudTrail Security Analysis Agent (MCP Version)")
    print("=" * 60)
    print(f"Database: {db_path or 'in-memory'}")
    print("=" * 60)
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. Example Query: {example}")
        print("-" * 50)
        
        try:
            result = agent.analyze(example)
            print(result)
        except Exception as e:
            print(f"Error: {e}")
        
        print("\n" + "=" * 60)