# CloudTrail Security Agent Benchmarking System

A comprehensive benchmarking framework for evaluating AI agents on CloudTrail security analysis tasks. Built with [Strands SDK](https://strandsagents.com/) and MotherDuck MCP server for local DuckDB queries.

## Overview

This system evaluates CloudTrail security agents using:
- **Ground truth Q&A dataset** from flAWS CloudTrail logs
- **LLM judge** for response evaluation against ground truth
- **Multi-dimensional reward scoring** (6 components including efficiency)
- **OpenTelemetry integration** for reasoning pattern analysis
- **Concurrent benchmarking** with configurable reward profiles

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone <repository-url>
cd cloud-logs-security-agent

# Install dependencies (requires Python 3.10+)
pip install -e .

# Install with OpenTelemetry support
pip install -e ".[otel]"

# Install MotherDuck MCP server
pip install uv
uvx mcp-server-motherduck
```

### 2. Setup Dataset

The system uses the **flAWS CloudTrail Security Q&A Dataset** from HuggingFace:

**🤗 Dataset**: [kachio/flaws-cloudtrail-security-qa](https://huggingface.co/datasets/kachio/flaws-cloudtrail-security-qa)

This dataset contains:
- **1,200+ Q&A pairs** generated from real flAWS CloudTrail logs
- **Multiple question types**: overview, services, errors, access patterns
- **Difficulty levels**: easy, medium, hard
- **DuckDB partitions** with 1.9M+ CloudTrail events

```bash
# Download dataset
git clone https://huggingface.co/datasets/odemzkolo/flaws-cloudtrail-security-qa data/flaws_cloudtrail_duckdb
```

### 3. Run Benchmark

```bash
# Basic benchmark with equal weights
python src/cloud_logs_security_agent/run_benchmark.py --limit 10

# With specific reward profile
python src/cloud_logs_security_agent/run_benchmark.py \
  --reward-profile accuracy \
  --limit 50 \
  --concurrent 3

# With OpenTelemetry tracing
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
python src/cloud_logs_security_agent/run_benchmark.py \
  --limit 20
```

## System Architecture

### Core Components

```
src/cloud_logs_security_agent/
├── agent.py              # CloudTrail agent using Strands SDK + MCP
├── judge.py              # LLM judge for response evaluation  
├── reward.py             # 6-dimensional reward function
├── benchmark.py          # Concurrent evaluation framework
├── telemetry.py          # OpenTelemetry metrics extraction
├── analyze_components.py # Data-driven component analysis
└── run_benchmark.py      # Main benchmark execution script
```

### Agent Architecture

The CloudTrail agent uses:
- **Strands SDK** for agent framework
- **MotherDuck MCP server** for local DuckDB access
- **SQL-based analysis** through MCP `query` tool
- **Automatic reasoning cycles** with tool usage tracking

### Evaluation Pipeline

1. **Agent Execution**: CloudTrail agent analyzes security questions
2. **Judge Evaluation**: LLM compares responses to ground truth
3. **Reward Calculation**: 6-dimensional scoring with efficiency metrics
4. **Telemetry Extraction**: OpenTelemetry captures reasoning patterns
5. **Analysis**: Component correlation analysis for optimization

## Reward Components

The system evaluates agents across **6 dimensions**:

1. **Correctness** (35%) - Factual accuracy vs ground truth
2. **Completeness** (20%) - All required information included
3. **Specificity** (15%) - Exact numbers and details provided
4. **Security Insight** (15%) - Security-relevant analysis quality
5. **Response Time** (10%) - Speed of response
6. **Efficiency** (5%) - Tool usage and reasoning patterns

### Efficiency Scoring

Tracks agent reasoning efficiency:
- **Reasoning cycles**: LLM inference iterations
- **Tool calls**: Total tool invocations
- **Tools per cycle**: Reasoning consistency

**Targets by difficulty**:
- Easy: ≤2 cycles, ≤3 tools
- Medium: ≤4 cycles, ≤6 tools  
- Hard: ≤6 cycles, ≤10 tools

## Reward Profiles

Choose evaluation focus:

```bash
# Equal weights baseline (recommended)
--reward-profile equal

# Accuracy-focused (60% correctness weight)
--reward-profile accuracy

# Speed-focused (20% response time + 10% efficiency)
--reward-profile speed

# Security-focused (30% security insight weight)
--reward-profile security
```

## OpenTelemetry Integration

Built-in telemetry captures:
- **Token usage** (input/output/total)
- **Reasoning cycles** and tool calls
- **Tool performance** (execution time, success rate)
- **Response timing** (end-to-end latency)

Enable with:
```bash
# Console tracing (debug)
export OTEL_ENABLE_CONSOLE=true

# OTLP export (Jaeger, etc.)
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

## Analysis Tools

### Component Analysis

After running benchmarks, analyze component correlations:

```bash
python src/cloud_logs_security_agent/analyze_components.py \
  benchmark_results/benchmark_results_20250108_123456.json
```

This generates:
- **Correlation analysis** between components and judge acceptance
- **Suggested optimal weights** based on data
- **Performance breakdown** by question type and difficulty
- **Visualization plots** (correlation heatmaps, distributions)

### Results Structure

```
benchmark_results/
├── benchmark_results_20250108_123456.json  # Detailed results
├── benchmark_summary_20250108_123456.json  # Summary metrics
├── benchmark_report.md                     # Human-readable report
└── component_analysis/                     # Analysis outputs
    ├── component_analysis_report.md
    ├── suggested_weights.json
    └── correlation_heatmap.png
```

## Dataset Details

### Q&A Dataset Format

```json
{
  "question": "What is the total number of CloudTrail events recorded between 2018-11-01 and 2019-01-27?",
  "answer": "The total number of CloudTrail events recorded in the given date range is 23054.",
  "question_type": "overview",
  "difficulty": "easy", 
  "time_range": "['2018-11-01', '2019-01-27']",
  "relevant_events": null,
  "how_realistic": 0.9,
  "model": "gpt-4o-mini-2024-07-18",
  "partition": "customer_201811_201901_questions"
}
```

### DuckDB Schema

CloudTrail events stored with key fields:
- `eventTime`, `eventName`, `eventSource`
- `sourceIPAddress`, `userIdentity`  
- `errorCode`, `errorMessage`
- `requestParameters`, `responseElements`
- `resources`, `awsRegion`

## Usage Examples

### Basic Agent Usage

```python
from src.cloud_logs_security_agent.agent import create_cloudtrail_agent

# Create agent for specific partition
agent = create_cloudtrail_agent(
    model="anthropic/claude-3-7-sonnet-20250219",
    db_path="data/flaws_cloudtrail_duckdb/partitions/customer_201811_201901.duckdb"
)

# Analyze with metrics
result = agent.analyze_with_metrics("What are the most common event types?")
print(f"Response: {result.message}")
print(f"Reasoning cycles: {result.metrics.get_summary()['total_cycles']}")
```

### Custom Benchmarking

```python
from src.cloud_logs_security_agent.benchmark import CloudTrailBenchmark
from src.cloud_logs_security_agent.judge import CloudTrailJudge
from src.cloud_logs_security_agent.agent import create_cloudtrail_agent

# Setup benchmark
def agent_factory(db_path=None):
    return create_cloudtrail_agent(db_path=db_path)

judge = CloudTrailJudge()
benchmark = CloudTrailBenchmark(agent_factory, judge)

# Run evaluation
results = await benchmark.run_benchmark(limit=100)
summary = benchmark.analyze_results(results)
benchmark.print_summary(summary)
```

## Configuration

### Environment Variables

```bash
# OpenTelemetry
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_ENABLE_CONSOLE=true

# Model configuration
export ANTHROPIC_API_KEY=your_key_here
export OPENAI_API_KEY=your_key_here

# MCP server settings
export DUCKDB_READ_ONLY=true
```

### Custom Reward Weights

```python
from src.cloud_logs_security_agent.reward import RewardWeights, CloudTrailRewardFunction

# Custom weights
weights = RewardWeights(
    correctness=0.5,
    completeness=0.2, 
    specificity=0.1,
    security_insight=0.1,
    response_time=0.05,
    efficiency=0.05
)

reward_fn = CloudTrailRewardFunction(weights=weights)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pytest tests/`
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use this benchmarking system or dataset in your research, please cite:

```bibtex
@dataset{kachio2025_flaws_cloudtrail,
  title={flAWS CloudTrail Security Q\&A Dataset},
  author={Kachio, Ode},
  year={2025},
  url={https://huggingface.co/datasets/odemzkolo/flaws-cloudtrail-security-qa},
  note={CloudTrail security analysis benchmark dataset with 1,200+ Q\&A pairs}
}
```

## Resources

- **🤗 Dataset**: [odemzkolo/flaws-cloudtrail-security-qa](https://huggingface.co/datasets/odemzkolo/flaws-cloudtrail-security-qa)
- **Strands SDK**: [https://strandsagents.com/](https://strandsagents.com/)
- **MotherDuck MCP**: [https://github.com/motherduckdb/mcp-server-motherduck](https://github.com/motherduckdb/mcp-server-motherduck)
- **flAWS**: [http://flaws.cloud/](http://flaws.cloud/)