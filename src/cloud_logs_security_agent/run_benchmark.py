"""Main script to run CloudTrail agent benchmark evaluation."""

import argparse
import asyncio
import logging
from pathlib import Path

from cloud_logs_security_agent.benchmark import CloudTrailBenchmark
from cloud_logs_security_agent.agent import CloudTrailAgent, create_cloudtrail_agent
from cloud_logs_security_agent.judge import CloudTrailJudge
from cloud_logs_security_agent.reward import (
    CloudTrailRewardFunction,
    create_accuracy_focused_weights,
    create_security_focused_weights,
    create_speed_focused_weights,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def run_benchmark():
    """Main function to run benchmark evaluation."""
    parser = argparse.ArgumentParser(description="Run CloudTrail agent benchmark")
    parser.add_argument(
        "--model", 
        default="anthropic/claude-3-7-sonnet-20250219",
        help="Model to use for the agent"
    )
    parser.add_argument(
        "--judge-model",
        default="openai/gpt-4o",
        help="Model to use for the judge"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of questions to evaluate"
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=3,
        help="Number of concurrent evaluations"
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark_results",
        help="Directory to save results"
    )
    parser.add_argument(
        "--reward-profile",
        choices=["balanced", "accuracy", "speed", "security", "equal"],
        default="equal",
        help="Reward function profile to use"
    )
    parser.add_argument(
        "--dataset",
        default="data/flaws_cloudtrail_duckdb/dataset.json",
        help="Path to QA dataset"
    )
    parser.add_argument(
        "--partitions-path",
        default="data/flaws_cloudtrail_duckdb/partitions",
        help="Path to DuckDB partition files"
    )
    
    args = parser.parse_args()
    
    # Initialize components
    logger.info(f"Using CloudTrail agent with model: {args.model}")
    
    # Create agent factory function
    def agent_factory(db_path: str = None) -> CloudTrailAgent:
        return create_cloudtrail_agent(model=args.model, db_path=db_path)
    
    logger.info(f"Initializing judge with model: {args.judge_model}")
    judge = CloudTrailJudge(model=args.judge_model)
    
    logger.info(f"Loading dataset from: {args.dataset}")
    benchmark = CloudTrailBenchmark(
        agent_factory=agent_factory, 
        judge=judge, 
        dataset_path=args.dataset,
        partitions_base_path=args.partitions_path
    )
    
    # Setup reward function
    if args.reward_profile == "equal":
        reward_fn = CloudTrailRewardFunction(equal_weights=True)
    else:
        reward_weights = {
            "balanced": None,  # Use default
            "accuracy": create_accuracy_focused_weights(),
            "speed": create_speed_focused_weights(),
            "security": create_security_focused_weights()
        }
        reward_fn = CloudTrailRewardFunction(weights=reward_weights[args.reward_profile])
    logger.info(f"Using reward profile: {args.reward_profile}")
    
    # Run benchmark
    logger.info(f"Starting benchmark evaluation (limit: {args.limit}, concurrent: {args.concurrent})")
    results = await benchmark.run_benchmark(
        limit=args.limit,
        concurrent_limit=args.concurrent
    )
    
    if not results:
        logger.error("No results obtained from benchmark")
        return
    
    # Calculate rewards for each result
    logger.info("Calculating reward scores...")
    for result in results:
        if result.success:
            reward_breakdown = reward_fn.calculate_reward(
                evaluation=result.evaluation,
                response_time=result.response_time,
                question_type=result.question_type,
                difficulty=result.difficulty
            )
            result.evaluation["reward"] = reward_breakdown.__dict__
    
    # Analyze results
    logger.info("Analyzing results...")
    summary = benchmark.analyze_results(results)
    
    # Print summary
    benchmark.print_summary(summary)
    
    # Print reward analysis
    successful_results = [r for r in results if r.success]
    if successful_results:
        avg_reward = sum(r.evaluation.get("reward", {}).get("total_score", 0) for r in successful_results) / len(successful_results)
        print(f"\nAverage Reward Score: {avg_reward:.3f}")
        
        # Reward breakdown by question type
        reward_by_type = {}
        for result in successful_results:
            qtype = result.question_type
            reward_score = result.evaluation.get("reward", {}).get("total_score", 0)
            if qtype not in reward_by_type:
                reward_by_type[qtype] = []
            reward_by_type[qtype].append(reward_score)
        
        print("\nReward Scores by Question Type:")
        for qtype, scores in reward_by_type.items():
            avg_score = sum(scores) / len(scores)
            print(f"  {qtype}: {avg_score:.3f} (n={len(scores)})")
    
    # Save results
    logger.info(f"Saving results to {args.output_dir}")
    benchmark.save_results(results, summary, args.output_dir)
    
    # Generate detailed report
    generate_detailed_report(results, summary, reward_fn, args.output_dir)
    
    logger.info("Benchmark completed successfully!")


def generate_detailed_report(results, summary, reward_fn, output_dir):
    """Generate a detailed markdown report of the benchmark results."""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    report_file = output_path / "benchmark_report.md"
    
    with open(report_file, 'w') as f:
        f.write("# CloudTrail Agent Benchmark Report\n\n")
        f.write(f"**Generated:** {summary.timestamp}\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- **Total Questions:** {summary.total_questions}\n")
        f.write(f"- **Successful Responses:** {summary.successful_responses}\n")
        f.write(f"- **Failed Responses:** {summary.failed_responses}\n")
        f.write(f"- **Success Rate:** {summary.successful_responses/summary.total_questions:.2%}\n")
        f.write(f"- **Average Score:** {summary.average_score:.3f}\n")
        f.write(f"- **Average Response Time:** {summary.average_response_time:.2f}s\n\n")
        
        if summary.by_question_type:
            f.write("## Performance by Question Type\n\n")
            f.write("| Question Type | Average Score | Count | Success Rate |\n")
            f.write("|---------------|---------------|-------|---------------|\n")
            for qtype, stats in summary.by_question_type.items():
                f.write(f"| {qtype} | {stats['average_score']:.3f} | {stats['count']} | {stats['success_rate']:.2%} |\n")
            f.write("\n")
        
        if summary.by_difficulty:
            f.write("## Performance by Difficulty\n\n")
            f.write("| Difficulty | Average Score | Count | Success Rate |\n")
            f.write("|------------|---------------|-------|---------------|\n")
            for difficulty, stats in summary.by_difficulty.items():
                f.write(f"| {difficulty} | {stats['average_score']:.3f} | {stats['count']} | {stats['success_rate']:.2%} |\n")
            f.write("\n")
        
        # Failed cases analysis
        failed_results = [r for r in results if not r.success]
        if failed_results:
            f.write("## Failed Cases\n\n")
            f.write(f"Total failed cases: {len(failed_results)}\n\n")
            for result in failed_results:
                f.write(f"**Question:** {result.question}\n")
                f.write(f"**Type:** {result.question_type}, **Difficulty:** {result.difficulty}\n")
                f.write(f"**Error:** {result.error}\n\n")
        
        f.write("## Example Responses\n\n")
        # Show a few example responses
        successful_results = [r for r in results if r.success]
        if successful_results:
            # Show best and worst performing examples
            sorted_results = sorted(successful_results, key=lambda x: x.evaluation.get("overall_score", 0), reverse=True)
            
            f.write("### Best Performing Response\n\n")
            best = sorted_results[0]
            f.write(f"**Question:** {best.question}\n")
            f.write(f"**Ground Truth:** {best.ground_truth}\n")
            f.write(f"**Agent Response:** {best.agent_answer}\n")
            f.write(f"**Score:** {best.evaluation.get('overall_score', 0):.3f}\n\n")
            
            if len(sorted_results) > 1:
                f.write("### Worst Performing Response\n\n")
                worst = sorted_results[-1]
                f.write(f"**Question:** {worst.question}\n")
                f.write(f"**Ground Truth:** {worst.ground_truth}\n")
                f.write(f"**Agent Response:** {worst.agent_answer}\n")
                f.write(f"**Score:** {worst.evaluation.get('overall_score', 0):.3f}\n\n")
    
    logger.info(f"Detailed report saved to {report_file}")


def main():
    """Entry point for the benchmark CLI."""
    asyncio.run(run_benchmark())


if __name__ == "__main__":
    main()