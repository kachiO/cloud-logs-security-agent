#!/usr/bin/env python3
"""
Generate synthetic Q&A dataset for CloudTrail logs using batch LLM generation.
Similar to ART·E's approach but adapted for security log analysis.

Example usage:
    uv run generate_cloudtrail_questions.py --db-dir /path/to/cloudtrail/logs --output-dir /path/to/output --model gpt-4.1-nano --use-batches --batch-size 2048 --num-batches 3
"""

import asyncio
import datetime
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb
import instructor
import litellm
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import track

load_dotenv()
console = Console()

litellm.cache = litellm.Cache(type="disk", disk_cache_path="./.litellm_cache")

client = instructor.from_litellm(litellm.acompletion)
# TODO: add instructor for parsing LLM responses


def default_serializer(obj):
    """Default serializer for JSON to handle datetime and date objects."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


@dataclass
class CloudTrailStats:
    total_events: int
    date_range: tuple
    unique_ips: int
    unique_principals: int
    error_rate: float
    top_services: List[tuple]
    top_errors: List[tuple]


class SecurityQuestion(BaseModel):
    question: str = Field(
        description="The natural language question about CloudTrail logs"
    )
    answer: str = Field(
        description="The correct answer to the question, or explanation why it's unanswerable",
    )
    question_type: str = Field(
        pattern="^(overview|access|services|errors|security|anomaly|incident|unanswerable)$",
        description="Type of question, one of [overview, access, services, errors, security, anomaly, incident, unanswerable]",
    )
    difficulty: str = Field(
        pattern="^(easy|medium|hard)$",
        description="Difficulty level of the question, one of [easy, medium, hard]",
    )
    time_range: List[str] = Field(
        description="The relevant date range for the question, as [start, end]"
    )
    relevant_events: List[str] = Field(
        default=None,
        description="List of relevant event names that relate to the question, can be null",
    )
    how_realistic: float = Field(
        le=1.0,
        ge=0.0,
        description="Realism score from 0.0 to 1.0, indicating how realistic the question is",
    )


class QuestionBatch(BaseModel):
    questions: List[SecurityQuestion]


def extract_database_stats(db_path: str, limit: int = 10) -> CloudTrailStats:
    """Extract key statistics from CloudTrail database."""
    conn = duckdb.connect(db_path, read_only=True)

    # Basic stats
    stats_query = """
    SELECT 
        COUNT(*) as total_events,
        MIN(eventtime)::VARCHAR as start_date,
        MAX(eventtime)::VARCHAR as end_date,
        COUNT(DISTINCT sourceipaddress) as unique_ips,
        COUNT(DISTINCT useridentity.principalid) as unique_principals,
        ROUND(100.0 * SUM(CASE WHEN errorcode IS NOT NULL AND errorcode != '' THEN 1 ELSE 0 END) / COUNT(*), 1) as error_rate
    FROM cloudtrail_logs
    """
    basic_stats = conn.execute(stats_query).fetchone()

    # Top services
    services_query = f"""
    SELECT eventsource, COUNT(*) as count
    FROM cloudtrail_logs
    GROUP BY eventsource
    ORDER BY count DESC
    LIMIT {limit}
    """
    top_services = conn.execute(services_query).fetchall()

    # Top errors
    errors_query = f"""
    SELECT eventname, errorcode, COUNT(*) as count
    FROM cloudtrail_logs
    WHERE errorcode IS NOT NULL AND errorcode != ''
    GROUP BY eventname, errorcode
    ORDER BY count DESC
    LIMIT {limit}
    """
    top_errors = conn.execute(errors_query).fetchall()

    conn.close()

    console.print(f"[green]Extracted stats from {db_path}[/green]")
    console.print(
        f"Total events: {basic_stats[0]:,}, Date range: {basic_stats[1]} to {basic_stats[2]}"
    )
    console.print(
        f"Unique IPs: {basic_stats[3]:,}, Unique Principals: {basic_stats[4]:,}"
    )
    console.print(f"Error rate: {basic_stats[5]}%")
    console.print(
        f"Top services: {len(top_services)} entries, Top errors: {len(top_errors)} entries"
    )
    console.print(f"Top services: {top_services}")
    console.print(f"Top errors: {top_errors}")
    return CloudTrailStats(
        total_events=basic_stats[0],
        date_range=(basic_stats[1], basic_stats[2]),
        unique_ips=basic_stats[3],
        unique_principals=basic_stats[4],
        error_rate=basic_stats[5],
        top_services=top_services,
        top_errors=top_errors,
    )


def get_event_batches(
    db_path: str, batch_size: int = 1000, num_batches: int = 5
) -> List[List[Dict]]:
    """Get batches of consecutive CloudTrail events."""
    conn = duckdb.connect(db_path, read_only=True)

    batches = []
    events_per_batch = batch_size // num_batches
    # Get total event count
    total_events = conn.execute("SELECT COUNT(*) FROM cloudtrail_logs").fetchone()[0]

    # Sample different time periods
    for i in range(num_batches):
        # Random offset to get different parts of the timeline
        offset = (total_events // num_batches) * i

        batch_query = f"""
        SELECT 
            eventtime,
            eventname,
            eventsource,
            sourceipaddress,
            useridentity,
            errorcode,
            errormessage,
            awsregion,
            requestparameters,
            responseelements
        FROM cloudtrail_logs
        ORDER BY eventtime
        LIMIT {events_per_batch}
        OFFSET {offset}
        """

        events = conn.execute(batch_query).fetchall()

        # Convert to dictionaries
        batch = []
        for event in events:
            batch.append(
                {
                    "eventtime": str(event[0]),
                    "eventname": event[1],
                    "eventsource": event[2],
                    "sourceipaddress": event[3],
                    "useridentity": event[4],
                    "errorcode": event[5],
                    "errormessage": event[6],
                    "awsregion": event[7],
                    "requestparameters": event[8],
                    "responseelements": event[9],
                }
            )

        if batch:
            batches.append(batch)

    conn.close()
    return batches


def discover_patterns(db_path: str, batch_size: int = 1000) -> Dict[str, Any]:
    """Dynamically discover patterns in CloudTrail data."""
    conn = duckdb.connect(db_path, read_only=True)

    limit = batch_size // 6  # Limit for each pattern analysis
    patterns = {
        "temporal": analyze_temporal_patterns(conn, limit=limit),
        "access": analyze_access_patterns(conn, limit=limit),
        "errors": analyze_error_patterns(conn, limit=limit),
        "services": analyze_service_patterns(conn, limit=limit),
        "anomalies": detect_anomalies(conn, limit=limit),
        "high_activity": other_interesting_patterns(conn, limit=limit),
    }

    conn.close()
    return patterns


def other_interesting_patterns(conn, limit: int = 10) -> List[Dict]:
    """Find high-volume IPs, failed operations, and other patterns."""
    patterns = []
    limit = limit // 3
    # High-volume IPs
    ip_query = f"""
    SELECT 
        sourceipaddress,
        COUNT(*) as event_count,
        COUNT(DISTINCT eventname) as unique_events,
        SUM(CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END) as error_count
    FROM cloudtrail_logs
    WHERE sourceipaddress NOT LIKE '%amazonaws.com%'
    GROUP BY sourceipaddress
    ORDER BY event_count DESC
    LIMIT {limit}
    """
    patterns.append(
        {"type": "high_volume_ips", "data": conn.execute(ip_query).fetchall()}
    )

    # Failed operations
    failed_query = f"""
    SELECT 
        DATE(eventtime) as event_date,
        COUNT(*) as daily_events,
        SUM(CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END) as daily_errors
    FROM cloudtrail_logs
    GROUP BY DATE(eventtime)
    ORDER BY daily_errors DESC
    LIMIT {limit}
    """
    patterns.append(
        {"type": "high_error_days", "data": conn.execute(failed_query).fetchall()}
    )

    return patterns


def analyze_temporal_patterns(conn, limit: int = 10) -> Dict:
    """Find temporal patterns like spikes, quiet periods, unusual hours."""
    query = f"""
    WITH hourly_stats AS (
        SELECT 
            DATE_TRUNC('hour', eventtime) as hour,
            COUNT(*) as event_count,
            COUNT(DISTINCT sourceipaddress) as unique_ips
        FROM cloudtrail_logs
        GROUP BY DATE_TRUNC('hour', eventtime)
    )
    SELECT 
        hour,
        event_count,
        unique_ips,
        event_count / NULLIF(AVG(event_count) OVER (), 0) as spike_ratio
    FROM hourly_stats
    ORDER BY spike_ratio DESC
    LIMIT {limit}
    """
    return {"hourly_spikes": conn.execute(query).fetchall()}


def analyze_access_patterns(conn, limit: int = 10) -> Dict:
    """Find unusual access patterns."""
    query = f"""
    SELECT 
        useridentity.type as user_type,
        sourceipaddress,
        COUNT(DISTINCT eventname) as unique_operations,
        COUNT(*) as total_events,
        SUM(CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END) as failed_events
    FROM cloudtrail_logs
    WHERE sourceipaddress NOT LIKE '%amazonaws.com%'
    GROUP BY useridentity.type, sourceipaddress
    HAVING COUNT(*) > 50
    ORDER BY unique_operations DESC
    LIMIT {limit}
    """
    return {"diverse_access": conn.execute(query).fetchall()}


def analyze_error_patterns(conn, limit: int = 5) -> Dict:
    """Find error clusters and patterns."""
    query = f"""
    WITH error_sequences AS (
        SELECT 
            sourceipaddress,
            eventname,
            errorcode,
            eventtime,
            LAG(eventtime) OVER (PARTITION BY sourceipaddress ORDER BY eventtime) as prev_time
        FROM cloudtrail_logs
        WHERE errorcode IS NOT NULL AND errorcode != ''
    )
    SELECT 
        sourceipaddress,
        eventname,
        errorcode,
        COUNT(*) as burst_count,
        AVG(EXTRACT(EPOCH FROM (eventtime - prev_time))) as avg_seconds_between
    FROM error_sequences
    WHERE prev_time IS NOT NULL
    GROUP BY sourceipaddress, eventname, errorcode
    HAVING COUNT(*) > 10
    ORDER BY burst_count DESC
    LIMIT {limit}
    """
    return {"error_bursts": conn.execute(query).fetchall()}


def analyze_service_patterns(conn, limit: int = 10) -> Dict:
    """Find service usage patterns."""
    query = f"""
    SELECT 
        eventsource,
        COUNT(DISTINCT useridentity.principalid) as unique_users,
        COUNT(DISTINCT DATE(eventtime)) as active_days,
        COUNT(*) as total_events,
        COUNT(DISTINCT eventname) as unique_operations
    FROM cloudtrail_logs
    GROUP BY eventsource
    HAVING COUNT(*) > 100
    ORDER BY unique_operations DESC
    LIMIT {limit}
    """
    return {"service_diversity": conn.execute(query).fetchall()}


def detect_anomalies(conn, limit: int = 10) -> Dict:
    """Detect statistical anomalies in the data."""
    # Find rare event combinations
    rare_combos = conn.execute(f"""
    SELECT 
        eventname,
        eventsource,
        useridentity.type,
        COUNT(*) as occurrence_count
    FROM cloudtrail_logs
    GROUP BY eventname, eventsource, useridentity.type
    HAVING COUNT(*) = 1
    LIMIT {limit}
    """).fetchall()

    # Find unusual time gaps
    time_gaps = conn.execute(f"""
    WITH ordered_events AS (
        SELECT 
            eventtime,
            LAG(eventtime) OVER (ORDER BY eventtime) as prev_time
        FROM cloudtrail_logs
    )
    SELECT 
        prev_time as gap_start,
        eventtime as gap_end,
        EXTRACT(EPOCH FROM (eventtime - prev_time))/3600 as gap_hours
    FROM ordered_events
    WHERE prev_time IS NOT NULL
    ORDER BY gap_hours DESC
    LIMIT {limit}
    """).fetchall()

    return {"rare_combinations": rare_combos, "time_gaps": time_gaps}


SYSTEM_PROMPT = """You are generating training data for a CloudTrail security analysis agent.

Given statistics and patterns from a CloudTrail database, generate realistic security-focused questions that a security incident responder might ask during an investigation. Include both answerable and unanswerable questions.

For each question, provide:
- question: The natural language question
- answer: The correct answer (or explanation why it's unanswerable)
- question_type: One of [overview, access, services, errors, security, anomaly, incident, unanswerable]
- difficulty: One of [easy, medium, hard]
- time_range: The relevant date range as [start, end]
- relevant_events: List of relevant event names (can be null)
- how_realistic: Score from 0.0 to 1.0

Generate a mix of:
1. Simple factual questions (3-4)
2. Analysis questions requiring correlation (2-3)
3. Security investigation questions (2-3)
4. Unanswerable questions to test faithfulness (3-4)

For unanswerable questions, the answer should explain why CloudTrail doesn't contain that information.

Return only a JSON array of question objects."""

BATCH_PROMPT = """You are generating training data for a CloudTrail security analysis agent.

Given a batch of consecutive CloudTrail events, generate realistic security-focused questions that a security analyst might ask about these specific events. Focus on patterns, anomalies, and security concerns visible in this batch.

For each question, provide:
- question: The natural language question about these specific events
- answer: The correct answer based on the events shown (or explanation why it's unanswerable)
- question_type: One of [overview, access, services, errors, security, anomaly, incident, unanswerable]
- difficulty: One of [easy, medium, hard]
- time_range: The actual time range of events in this batch
- relevant_events: List of specific event names from the batch that relate to the question
- how_realistic: Score from 0.0 to 1.0

Focus on:
1. Temporal patterns in this sequence (rapid events, gaps, unusual timing)
2. Error sequences or repeated failures
3. Unusual access patterns or reconnaissance behavior
4. Service-specific security concerns
5. Questions that require correlating multiple events in the batch

Return only a JSON array of question objects wrapped in {"questions": [...]}."""


async def generate_questions_from_batch(
    event_batch: List[Dict], db_name: str, model: str = "gpt-4.1-nano"
) -> List[SecurityQuestion]:
    """Generate questions from a batch of consecutive events."""
    console.print(
        f"[blue]Generating questions for batch of {len(event_batch)} events[/blue]"
    )
    # Get time range from batch
    if event_batch:
        time_range = [event_batch[0]["eventtime"], event_batch[-1]["eventtime"]]
    else:
        time_range = ["unknown", "unknown"]

    context = {
        "database": db_name,
        "event_count": len(event_batch),
        "time_range": time_range,
        "events": event_batch,
    }

    try:
        batch_response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": BATCH_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        context, indent=2, default=default_serializer
                    ),
                },
            ],
            response_model=QuestionBatch,
            max_retries=3,
            temperature=0.7,
            caching=True,
        )

        return [q for q in batch_response.questions if q.how_realistic > 0.7]
    except Exception as e:
        console.print(f"[red]Error generating batch questions: {e}[/red]")
        return []


async def generate_questions_for_database(
    db_path: str,
    model: str = "gpt-4.1-nano",
    use_batches: bool = False,
    batch_size: int = 1000,
    num_batches: Optional[int] = None,
) -> List[SecurityQuestion]:
    """Generate questions for a single CloudTrail database."""

    db_name = Path(db_path).stem
    all_questions = []

    stats = extract_database_stats(db_path)
    patterns = discover_patterns(db_path, batch_size=batch_size)

    context = {
        "database": db_name,
        "statistics": asdict(stats),
        "patterns": patterns,
    }

    try:
        pattern_response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        context, indent=2, default=default_serializer
                    ),
                },
            ],
            response_model=QuestionBatch,
            max_retries=3,
            temperature=0.7,
            caching=True,
        )

        pattern_questions = [
            q for q in pattern_response.questions if q.how_realistic > 0.7
        ]
        all_questions.extend(pattern_questions)
        console.print(
            f"[green]Generated {len(pattern_questions)} pattern-based questions[/green]"
        )
    except Exception as e:
        console.print(f"[red]Error generating pattern questions: {e}[/red]")

    # Batch-based generation
    if use_batches:
        event_batches = get_event_batches(db_path, batch_size, num_batches)
        console.print(f"[blue]Processing {len(event_batches)} event batches[/blue]")

        for i, batch in enumerate(event_batches):
            batch_questions = await generate_questions_from_batch(batch, db_name, model)
            all_questions.extend(batch_questions)
            console.print(
                f"[green]Batch {i + 1}: Generated {len(batch_questions)} questions[/green]"
            )

    return all_questions


async def process_all_databases(
    db_file_or_dir: Path,
    output_dir: Path,
    model: str = "gpt-4.1-nano",
    use_batches: bool = False,
    batch_size: int = 2048,
    num_batches: int = 3,
):
    """Process all CloudTrail databases and generate questions."""
    if Path(db_file_or_dir).is_file():
        db_files = [db_file_or_dir]
        console.print(f"[green]Processing single database: {db_file_or_dir}[/green]")
    if Path(db_file_or_dir).is_dir():
        db_files = sorted(db_file_or_dir.glob("*.duckdb"))
        console.print(f"[green]Found {len(db_files)} databases to process[/green]")

    output_dir.mkdir(exist_ok=True)

    for db_file in track(db_files, description="Processing databases"):
        try:
            questions = await generate_questions_for_database(
                str(db_file),
                model,
                use_batches=use_batches,
                batch_size=batch_size,
                num_batches=num_batches,
            )

            # Save questions
            output_file = output_dir / f"{db_file.stem}_questions.jsonl"
            with open(output_file, "w") as f:
                for q in questions:
                    f.write(q.model_dump_json() + "\n")

            console.print(
                f"[blue]Generated {len(questions)} total questions for {db_file.stem}[/blue]"
            )

        except Exception as e:
            console.print(f"[red]Error processing {db_file}: {e}[/red]")
            continue


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate security questions from CloudTrail databases"
    )
    file_or_dir_grp = parser.add_mutually_exclusive_group(required=True)
    file_or_dir_grp.add_argument(
        "--db-file",
        type=Path,
        help="Single CloudTrail DuckDB database file to process",
    )
    file_or_dir_grp.add_argument(
        "--db-dir",
        type=Path,
        help="Directory containing CloudTrail DuckDB databases to process",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default="data/flaws/cloudtrail_questions",
        help="Directory to save generated questions",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4.1-nano",
        help="LLM model to use for question generation",
    )
    parser.add_argument(
        "--use-batches",
        action="store_true",
        help="Generate questions from event batches in addition to patterns",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2048,
        help="Number of log events per batch (default: 2048)",
    )
    parser.add_argument(
        "--num-batches",
        type=int,
        default=3,
        help="Number of event batches to process per database (default: 3)",
    )

    args = parser.parse_args()

    console.print(
        f"[green]Starting question generation with model {args.model}[/green]"
    )
    if args.use_batches:
        console.print(
            f"[blue]Using batch mode: {args.num_batches} batches of {args.batch_size} events[/blue]"
        )

    batch_size = min(
        args.batch_size, 2048
    )  # Limit batch size to prevent too large requests
    output_dir = Path(args.output_dir) / f"{args.model.replace('.', '_').replace('/', '_')}"
    output_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[blue]Output will be saved to {output_dir}[/blue]")
    asyncio.run(
        process_all_databases(
            db_file_or_dir=args.db_dir or args.db_file,
            output_dir=output_dir,
            model=args.model,
            use_batches=args.use_batches,
            batch_size=args.batch_size,
            num_batches=args.num_batches,
        )
    )
