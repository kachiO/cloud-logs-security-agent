# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CloudTrail Security Agent Benchmarking System that evaluates AI agents on CloudTrail security analysis tasks. The system uses:
- **Strands SDK** for agent framework
- **MotherDuck MCP server** for DuckDB database queries
- **OpenTelemetry** for telemetry and metrics
- **Multi-dimensional reward scoring** for agent evaluation

## Development Commands

### Installation
```bash
# Install project dependencies
uv pip install -e .

# Install with OpenTelemetry support
uv pip install -e ".[otel]"

# Install dev dependencies
uv pip install -e ".[dev]"
```

### Running the System
```bash
# Run basic benchmark (using entrypoint script)
uv run benchmark --limit 10

# Run with specific reward profile
uv run benchmark --reward-profile accuracy --limit 50 --concurrent 3

# Run with OpenTelemetry tracing
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 uv run benchmark --limit 20

# Alternative: Run directly with uv run
uv run python src/cloud_logs_security_agent/run_benchmark.py --limit 10
```

### Analysis Commands
```bash
# Analyze benchmark results (using entrypoint script)
uv run analyze-components benchmark_results/benchmark_results_20250108_123456.json

# Validate data partitions (using entrypoint script)
uv run validate-partitions --partitions-dir data/flaws_cloudtrail_duckdb/partitions

# Generate Q&A dataset (using entrypoint script)
uv run generate-questions --db-dir data/flaws_cloudtrail_duckdb/partitions --output-dir data/questions

# Alternative: Run directly with uv run
uv run python src/cloud_logs_security_agent/analyze_components.py benchmark_results/benchmark_results_20250108_123456.json
uv run python src/cloud_logs_security_agent/data/flaws/validate_partitions.py
uv run python src/cloud_logs_security_agent/data/flaws/generate_cloudtrail_questions.py --db-dir data/flaws_cloudtrail_duckdb/partitions
```

## Architecture

### Core Components
- **`agent.py`**: CloudTrail agent using Strands SDK + MCP for SQL queries
- **`judge.py`**: LLM judge for evaluating agent responses against ground truth
- **`benchmark.py`**: Concurrent evaluation framework with multi-dimensional scoring
- **`reward.py`**: 6-dimensional reward function (correctness, completeness, specificity, security insight, response time, efficiency)
- **`telemetry.py`**: OpenTelemetry integration for metrics extraction
- **`run_benchmark.py`**: Main CLI for running benchmarks

### Data Pipeline
- **`data/flaws/`**: Tools for processing flAWS CloudTrail dataset
- **DuckDB partitions**: Time-based partitioning of CloudTrail events
- **Q&A dataset**: Ground truth questions/answers for benchmarking

### Agent Architecture
The CloudTrail agent operates through:
1. **MCP Client**: Connects to MotherDuck MCP server for DuckDB queries
2. **SQL Analysis**: Executes security-focused SQL queries on CloudTrail data
3. **Reasoning Cycles**: Iterative analysis with tool usage tracking
4. **Metrics Collection**: OpenTelemetry spans for performance monitoring

### Database Schema
CloudTrail events in `cloudtrail_events` table with key columns:
- `eventTime`, `eventName`, `eventSource`
- `sourceIPAddress`, `userIdentity` 
- `errorCode`, `errorMessage`
- `requestParameters`, `responseElements`
- `resources`, `awsRegion`

## Code Style Guidelines

Keep code simple and short as possible. Avoid verbose code. Practice YAGNI, DRY, and/or SOLID where applicable. No emoji's in the code.
Aim for the code to be easy to read and review by a human.
Use rich logging instead of print statements.