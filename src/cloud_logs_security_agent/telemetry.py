"""OpenTelemetry telemetry setup for CloudTrail agent benchmarking."""

import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from strands.telemetry import StrandsTelemetry

logger = logging.getLogger(__name__)


@dataclass
class AgentExecutionMetrics:
    """Metrics extracted from agent execution."""
    
    # Basic execution metrics
    total_tokens: int
    input_tokens: int
    output_tokens: int
    response_time: float
    
    # Agent reasoning metrics
    reasoning_cycles: int
    tool_calls: int
    unique_tools: int
    
    # Tool performance
    avg_tool_execution_time: float
    tool_success_rate: float
    
    # Efficiency metrics
    tokens_per_cycle: float
    tools_per_cycle: float


class CloudTrailTelemetry:
    """Telemetry setup and metrics extraction for CloudTrail agents."""
    
    def __init__(self, enable_console_export: bool = False, enable_otlp: bool = False):
        """Initialize telemetry.
        
        Args:
            enable_console_export: Whether to enable console tracing output
            enable_otlp: Whether to enable OTLP export
        """
        self.strands_telemetry = StrandsTelemetry()
        
        if enable_console_export:
            self.strands_telemetry.setup_console_exporter()
            logger.info("Enabled console trace export")
        
        if enable_otlp:
            self.strands_telemetry.setup_otlp_exporter()
            logger.info("Enabled OTLP trace export")
    
    def extract_metrics_from_result(self, agent_result) -> AgentExecutionMetrics:
        """Extract comprehensive metrics from agent result.
        
        Args:
            agent_result: Result from agent execution with metrics
            
        Returns:
            Structured metrics for analysis
        """
        try:
            metrics = agent_result.metrics
            summary = metrics.get_summary()
            
            # Basic token usage
            usage = metrics.accumulated_usage
            total_tokens = usage.get('totalTokens', 0)
            input_tokens = usage.get('inputTokens', 0)
            output_tokens = usage.get('outputTokens', 0)
            
            # Extract reasoning cycles from summary
            reasoning_cycles = summary.get('total_cycles', 0)
            
            # Tool metrics
            tool_metrics = metrics.tool_metrics
            tool_calls = sum(tool.get('call_count', 0) for tool in tool_metrics.values())
            unique_tools = len([tool for tool in tool_metrics.keys() if tool_metrics[tool].get('call_count', 0) > 0])
            
            # Tool performance calculations
            tool_times = [tool.get('avg_execution_time', 0) for tool in tool_metrics.values() if tool.get('call_count', 0) > 0]
            avg_tool_execution_time = sum(tool_times) / len(tool_times) if tool_times else 0.0
            
            tool_successes = [tool.get('success_rate', 0) for tool in tool_metrics.values() if tool.get('call_count', 0) > 0]
            tool_success_rate = sum(tool_successes) / len(tool_successes) if tool_successes else 1.0
            
            # Response time from summary or calculate
            response_time = summary.get('total_execution_time', 0.0)
            
            # Efficiency calculations
            tokens_per_cycle = total_tokens / reasoning_cycles if reasoning_cycles > 0 else 0.0
            tools_per_cycle = tool_calls / reasoning_cycles if reasoning_cycles > 0 else 0.0
            
            return AgentExecutionMetrics(
                total_tokens=total_tokens,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                response_time=response_time,
                reasoning_cycles=reasoning_cycles,
                tool_calls=tool_calls,
                unique_tools=unique_tools,
                avg_tool_execution_time=avg_tool_execution_time,
                tool_success_rate=tool_success_rate,
                tokens_per_cycle=tokens_per_cycle,
                tools_per_cycle=tools_per_cycle
            )
            
        except Exception as e:
            logger.error(f"Failed to extract metrics: {e}")
            # Return default metrics on failure
            return AgentExecutionMetrics(
                total_tokens=0,
                input_tokens=0,
                output_tokens=0,
                response_time=0.0,
                reasoning_cycles=0,
                tool_calls=0,
                unique_tools=0,
                avg_tool_execution_time=0.0,
                tool_success_rate=0.0,
                tokens_per_cycle=0.0,
                tools_per_cycle=0.0
            )
    
    def get_efficiency_score(self, metrics: AgentExecutionMetrics, difficulty: str) -> float:
        """Calculate efficiency score based on agent metrics.
        
        Args:
            metrics: Agent execution metrics
            difficulty: Question difficulty level
            
        Returns:
            Efficiency score (0-1)
        """
        # Define efficiency targets by difficulty
        efficiency_targets = {
            "easy": {"max_cycles": 2, "max_tools": 3},
            "medium": {"max_cycles": 4, "max_tools": 6},
            "hard": {"max_cycles": 6, "max_tools": 10}
        }
        
        targets = efficiency_targets.get(difficulty, efficiency_targets["medium"])
        
        # Score reasoning cycles efficiency
        cycle_score = min(1.0, targets["max_cycles"] / max(1, metrics.reasoning_cycles))
        
        # Score tool usage efficiency
        tool_score = min(1.0, targets["max_tools"] / max(1, metrics.tool_calls))
        
        # Combined efficiency score
        efficiency_score = (cycle_score * 0.6 + tool_score * 0.4)
        
        return efficiency_score
    
    def get_detailed_metrics(self, agent_result) -> Dict[str, Any]:
        """Get detailed metrics dictionary for analysis.
        
        Args:
            agent_result: Result from agent execution
            
        Returns:
            Dictionary with all available metrics
        """
        metrics = self.extract_metrics_from_result(agent_result)
        
        return {
            "tokens": {
                "total": metrics.total_tokens,
                "input": metrics.input_tokens,
                "output": metrics.output_tokens,
                "per_cycle": metrics.tokens_per_cycle
            },
            "reasoning": {
                "cycles": metrics.reasoning_cycles,
                "response_time": metrics.response_time
            },
            "tools": {
                "total_calls": metrics.tool_calls,
                "unique_tools": metrics.unique_tools,
                "calls_per_cycle": metrics.tools_per_cycle,
                "avg_execution_time": metrics.avg_tool_execution_time,
                "success_rate": metrics.tool_success_rate
            },
            "efficiency": {
                "tokens_per_cycle": metrics.tokens_per_cycle,
                "tools_per_cycle": metrics.tools_per_cycle
            }
        }


def setup_telemetry_for_benchmark(
    enable_console: bool = False,
    enable_otlp: bool = False,
    otlp_endpoint: Optional[str] = None
) -> CloudTrailTelemetry:
    """Setup telemetry for benchmark runs.
    
    Args:
        enable_console: Enable console trace export for debugging
        enable_otlp: Enable OTLP export to observability platform
        otlp_endpoint: OTLP endpoint URL (if different from env var)
        
    Returns:
        Configured telemetry instance
    """
    if otlp_endpoint:
        import os
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = otlp_endpoint
    
    telemetry = CloudTrailTelemetry(
        enable_console_export=enable_console,
        enable_otlp=enable_otlp
    )
    
    logger.info("Telemetry setup complete")
    return telemetry


# Example usage
if __name__ == "__main__":
    # Setup telemetry
    telemetry = setup_telemetry_for_benchmark(enable_console=True)
    
    # This would be used in benchmark.py to extract metrics from agent results
    print("Telemetry configured for CloudTrail agent benchmarking")