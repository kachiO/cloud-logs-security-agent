# Cloud Security Incident Response Agent

An AI agent trained with reinforcement learning to assist with cloud security incident response by analyzing CloudTrail, VPC Flow Logs, and other AWS security logs.

## Quick Start

### 1. Setup Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Or if using pip install from pyproject.toml
pip install -e .
```

### 2. Import CloudTrail Logs

The first step is to import your CloudTrail logs into DuckDB for fast querying:

```bash
# Import flAWS CloudTrail logs into DuckDB
python setup_cloudtrail_db.py
```

This script will:
- Process all compressed CloudTrail JSON files from `data/flaws/data/flaws_cloudtrail_logs/`
- Extract and normalize log entries with proper schema
- Create optimized indexes for fast querying
- Generate a `data/cloudtrail_logs.duckdb` database

### 3. Verify Database Creation

After running the script, you should see output like:

```
✅ CloudTrail logs successfully imported into DuckDB!
Database location: /Users/kachio/Developer/cloud-logs-security-agent/data/cloudtrail_logs.duckdb

Total records imported: XXXXX
Unique event types: XX
Date range: YYYY-MM-DD to YYYY-MM-DD
```

## Project Structure

```
cloud-logs-security-agent/
├── src/cloud_logs_security_agent/
│   ├── tools/           # Log search and retrieval tools
│   ├── data/            # Synthetic training data
│   ├── models/          # Trained model storage
│   ├── rollout.py       # Agent execution logic
│   ├── reward.py        # Reward function for training
│   ├── train.py         # RL training pipeline
│   └── evaluate.py      # Evaluation framework
├── data/                # Database and raw data storage
├── setup_cloudtrail_db.py  # Database setup script
└── requirements.txt     # Python dependencies
```

## Next Steps

1. **Run the database setup script** to import CloudTrail logs
2. **Generate synthetic training scenarios** based on the imported logs
3. **Train the agent** using reinforcement learning (GRPO)
4. **Evaluate performance** on security incident response tasks

## Database Schema

The CloudTrail events are stored with the following key fields:

- `event_id`, `event_time`, `event_name`, `event_source`
- `user_identity_*` fields for authentication context
- `aws_region`, `source_ip_address`, `user_agent`
- `request_parameters`, `response_elements` (JSON)
- `error_code`, `error_message` for failed operations
- `raw_record` containing the full original log entry

Optimized indexes are created for common security queries on event time, event name, user identity, source IP, and error codes.
