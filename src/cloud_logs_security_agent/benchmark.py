"""Benchmark framework for evaluating CloudTrail agent performance."""

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cloud_logs_security_agent.agent import CloudTrailAgent
from cloud_logs_security_agent.judge import CloudTrailJudge, CloudTrailQuestion

logger = logging.getLogger(__name__)

@dataclass
class BenchmarkResult:
    """Single benchmark evaluation result."""
    question_id: str
    question: str
    question_type: str
    difficulty: str
    time_range: str
    partition: str
    ground_truth: str
    agent_answer: str
    evaluation: Dict[str, Any]
    response_time: float
    success: bool
    error: Optional[str] = None


@dataclass
class BenchmarkSummary:
    """Summary of benchmark results."""
    total_questions: int
    successful_responses: int
    failed_responses: int
    average_score: float
    average_response_time: float
    by_question_type: Dict[str, Dict[str, float]]
    by_difficulty: Dict[str, Dict[str, float]]
    timestamp: str


class CloudTrailBenchmark:
    """Benchmark framework for CloudTrail agent evaluation."""
    
    def __init__(
        self,
        agent_factory,  # Function to create agents
        judge: CloudTrailJudge,
        dataset_path: str = "data/flaws_cloudtrail_duckdb/dataset.json",
        partitions_base_path: str = "data/flaws_cloudtrail_duckdb/partitions"
    ):
        """Initialize benchmark framework.
        
        Args:
            agent_factory: Function to create CloudTrail agents (takes model and db_path)
            judge: Judge for response evaluation
            dataset_path: Path to the QA dataset
            partitions_base_path: Base path to partition files
        """
        self.agent_factory = agent_factory
        self.judge = judge
        self.dataset_path = Path(dataset_path)
        self.partitions_base_path = Path(partitions_base_path)
        
    def load_dataset(self, limit: Optional[int] = None) -> List[CloudTrailQuestion]:
        """Load the QA dataset.
        
        Args:
            limit: Optional limit on number of questions to load
            
        Returns:
            List of CloudTrail questions
        """
        try:
            with open(self.dataset_path, 'r') as f:
                data = json.load(f)
            
            questions = []
            for i, item in enumerate(data):
                if limit and i >= limit:
                    break
                    
                question = CloudTrailQuestion(
                    question=item["question"],
                    answer=item["answer"],
                    question_type=item["question_type"],
                    difficulty=item["difficulty"],
                    time_range=item["time_range"],
                    relevant_events=item.get("relevant_events", ""),
                    partition=item["partition"]
                )
                questions.append(question)
            
            logger.info(f"Loaded {len(questions)} questions from dataset")
            return questions
            
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return []
    
    async def evaluate_single_question(
        self,
        question: CloudTrailQuestion,
        question_id: str
    ) -> BenchmarkResult:
        """Evaluate agent on a single question.
        
        Args:
            question: Question to evaluate
            question_id: Unique identifier for the question
            
        Returns:
            Benchmark result for the question
        """
        start_time = time.time()
        
        try:
            # Create agent for the specific partition
            partition_db_path = self.partitions_base_path / f"{question.partition}.duckdb"
            agent = self.agent_factory(db_path=str(partition_db_path))
            
            # Get agent response
            agent_answer = await agent.analyze_async(question.question)
            
            response_time = time.time() - start_time
            
            # Evaluate response
            evaluation = await self.judge.evaluate_response(question, agent_answer)
            
            return BenchmarkResult(
                question_id=question_id,
                question=question.question,
                question_type=question.question_type,
                difficulty=question.difficulty,
                time_range=question.time_range,
                partition=question.partition,
                ground_truth=question.answer,
                agent_answer=agent_answer,
                evaluation=evaluation,
                response_time=response_time,
                success=True
            )
            
        except Exception as e:
            logger.error(f"Failed to evaluate question {question_id}: {e}")
            return BenchmarkResult(
                question_id=question_id,
                question=question.question,
                question_type=question.question_type,
                difficulty=question.difficulty,
                time_range=question.time_range,
                partition=question.partition,
                ground_truth=question.answer,
                agent_answer="",
                evaluation={},
                response_time=time.time() - start_time,
                success=False,
                error=str(e)
            )
    
    async def run_benchmark(
        self,
        limit: Optional[int] = None,
        concurrent_limit: int = 5
    ) -> List[BenchmarkResult]:
        """Run benchmark evaluation on the dataset.
        
        Args:
            limit: Optional limit on number of questions
            concurrent_limit: Maximum concurrent evaluations
            
        Returns:
            List of benchmark results
        """
        questions = self.load_dataset(limit)
        if not questions:
            logger.error("No questions loaded for benchmark")
            return []
        
        logger.info(f"Running benchmark on {len(questions)} questions")
        
        # Create semaphore for concurrent limit
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        async def evaluate_with_semaphore(question, question_id):
            async with semaphore:
                return await self.evaluate_single_question(question, question_id)
        
        # Run evaluations concurrently
        tasks = [
            evaluate_with_semaphore(question, f"q_{i}")
            for i, question in enumerate(questions)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = [
            result for result in results
            if isinstance(result, BenchmarkResult)
        ]
        
        logger.info(f"Completed benchmark: {len(valid_results)} results")
        return valid_results
    
    def analyze_results(self, results: List[BenchmarkResult]) -> BenchmarkSummary:
        """Analyze benchmark results and generate summary.
        
        Args:
            results: List of benchmark results
            
        Returns:
            Benchmark summary
        """
        if not results:
            return BenchmarkSummary(
                total_questions=0,
                successful_responses=0,
                failed_responses=0,
                average_score=0.0,
                average_response_time=0.0,
                by_question_type={},
                by_difficulty={},
                timestamp=datetime.now().isoformat()
            )
        
        # Overall statistics
        total_questions = len(results)
        successful_responses = sum(1 for r in results if r.success)
        failed_responses = total_questions - successful_responses
        
        # Score and timing calculations
        successful_results = [r for r in results if r.success]
        if successful_results:
            scores = [r.evaluation.get("overall_score", 0.0) for r in successful_results]
            average_score = sum(scores) / len(scores)
            
            response_times = [r.response_time for r in successful_results]
            average_response_time = sum(response_times) / len(response_times)
        else:
            average_score = 0.0
            average_response_time = 0.0
        
        # Analysis by question type
        by_question_type = {}
        question_types = set(r.question_type for r in results)
        for qtype in question_types:
            type_results = [r for r in results if r.question_type == qtype and r.success]
            if type_results:
                type_scores = [r.evaluation.get("overall_score", 0.0) for r in type_results]
                by_question_type[qtype] = {
                    "count": len(type_results),
                    "average_score": sum(type_scores) / len(type_scores),
                    "success_rate": len(type_results) / len([r for r in results if r.question_type == qtype])
                }
        
        # Analysis by difficulty
        by_difficulty = {}
        difficulties = set(r.difficulty for r in results)
        for difficulty in difficulties:
            diff_results = [r for r in results if r.difficulty == difficulty and r.success]
            if diff_results:
                diff_scores = [r.evaluation.get("overall_score", 0.0) for r in diff_results]
                by_difficulty[difficulty] = {
                    "count": len(diff_results),
                    "average_score": sum(diff_scores) / len(diff_scores),
                    "success_rate": len(diff_results) / len([r for r in results if r.difficulty == difficulty])
                }
        
        return BenchmarkSummary(
            total_questions=total_questions,
            successful_responses=successful_responses,
            failed_responses=failed_responses,
            average_score=average_score,
            average_response_time=average_response_time,
            by_question_type=by_question_type,
            by_difficulty=by_difficulty,
            timestamp=datetime.now().isoformat()
        )
    
    def save_results(
        self,
        results: List[BenchmarkResult],
        summary: BenchmarkSummary,
        output_dir: str = "benchmark_results"
    ) -> None:
        """Save benchmark results to files.
        
        Args:
            results: Benchmark results
            summary: Benchmark summary
            output_dir: Directory to save results
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save detailed results
        results_file = output_path / f"benchmark_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        
        # Save summary
        summary_file = output_path / f"benchmark_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(asdict(summary), f, indent=2)
        
        logger.info(f"Results saved to {output_path}")
    
    def print_summary(self, summary: BenchmarkSummary) -> None:
        """Print benchmark summary to console.
        
        Args:
            summary: Benchmark summary to print
        """
        print("\n" + "="*60)
        print("CLOUDTRAIL AGENT BENCHMARK SUMMARY")
        print("="*60)
        print(f"Total Questions: {summary.total_questions}")
        print(f"Successful Responses: {summary.successful_responses}")
        print(f"Failed Responses: {summary.failed_responses}")
        print(f"Success Rate: {summary.successful_responses/summary.total_questions:.2%}")
        print(f"Average Score: {summary.average_score:.3f}")
        print(f"Average Response Time: {summary.average_response_time:.2f}s")
        
        if summary.by_question_type:
            print("\nBy Question Type:")
            print("-" * 40)
            for qtype, stats in summary.by_question_type.items():
                print(f"  {qtype}: {stats['average_score']:.3f} (n={stats['count']})")
        
        if summary.by_difficulty:
            print("\nBy Difficulty:")
            print("-" * 40)
            for difficulty, stats in summary.by_difficulty.items():
                print(f"  {difficulty}: {stats['average_score']:.3f} (n={stats['count']})")
        
        print("="*60)


# Example usage and main function
async def main():
    """Main function to run benchmark."""
    from cloudtrail_agent import create_cloudtrail_agent
    
    # Create agent factory
    def agent_factory(db_path: str = None) -> CloudTrailAgent:
        return create_cloudtrail_agent(
            model="anthropic/claude-3-7-sonnet-20250219",
            db_path=db_path
        )
    
    # Initialize components
    judge = CloudTrailJudge(model="openai/gpt-4o")
    benchmark = CloudTrailBenchmark(agent_factory, judge)
    
    # Run benchmark on a subset
    results = await benchmark.run_benchmark(limit=10, concurrent_limit=3)
    
    # Analyze results
    summary = benchmark.analyze_results(results)
    
    # Print summary
    benchmark.print_summary(summary)
    
    # Save results
    benchmark.save_results(results, summary)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())