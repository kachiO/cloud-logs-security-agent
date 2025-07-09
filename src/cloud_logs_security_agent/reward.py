"""Reward function for CloudTrail agent performance evaluation."""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict

logger = logging.getLogger(__name__)


class RewardComponent(Enum):
    """Components that contribute to the reward score."""

    CORRECTNESS = "correctness"
    COMPLETENESS = "completeness"
    SPECIFICITY = "specificity"
    SECURITY_INSIGHT = "security_insight"
    RESPONSE_TIME = "response_time"
    EFFICIENCY = "efficiency"


@dataclass
class RewardWeights:
    """Weights for different reward components."""

    correctness: float = 0.35
    completeness: float = 0.2
    specificity: float = 0.15
    security_insight: float = 0.15
    response_time: float = 0.1
    efficiency: float = 0.05

    def __post_init__(self):
        """Validate weights sum to 1.0."""
        total = (
            self.correctness
            + self.completeness
            + self.specificity
            + self.security_insight
            + self.response_time
            + self.efficiency
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {total}")


@dataclass
class RewardBreakdown:
    """Breakdown of reward components."""

    correctness_score: float
    completeness_score: float
    specificity_score: float
    security_insight_score: float
    response_time_score: float
    efficiency_score: float
    total_score: float
    explanation: str


class CloudTrailRewardFunction:
    """Reward function for evaluating CloudTrail agent responses."""

    def __init__(self, weights: RewardWeights = None, equal_weights: bool = False):
        """Initialize reward function.

        Args:
            weights: Custom weights for reward components
            equal_weights: If True, use equal weights (0.2 each) for all components
        """
        if equal_weights:
            self.weights = RewardWeights(
                correctness=1/6,
                completeness=1/6,
                specificity=1/6,
                security_insight=1/6,
                response_time=1/6,
                efficiency=1/6
            )
        else:
            self.weights = weights or RewardWeights()

    def calculate_reward(
        self,
        evaluation: Dict[str, Any],
        response_time: float,
        question_type: str,
        difficulty: str,
        agent_metrics: Dict[str, Any] = None,
    ) -> RewardBreakdown:
        """Calculate reward score for an agent response.

        Args:
            evaluation: Evaluation results from judge
            response_time: Time taken to respond
            question_type: Type of question (overview, services, errors, etc.)
            difficulty: Difficulty level (easy, medium, hard)
            agent_metrics: Optional metrics from agent execution (tool calls, cycles, etc.)

        Returns:
            Detailed reward breakdown
        """
        # Extract correctness evaluation
        correctness_eval = evaluation.get("correctness", {})

        # Calculate individual component scores
        correctness_score = self._calculate_correctness_score(correctness_eval)
        completeness_score = self._calculate_completeness_score(correctness_eval)
        specificity_score = self._calculate_specificity_score(
            correctness_eval, question_type
        )
        security_insight_score = self._calculate_security_insight_score(
            correctness_eval, question_type
        )
        response_time_score = self._calculate_response_time_score(
            response_time, difficulty
        )
        efficiency_score = self._calculate_efficiency_score(
            agent_metrics or {}, difficulty
        )

        # Calculate weighted total
        total_score = (
            correctness_score * self.weights.correctness
            + completeness_score * self.weights.completeness
            + specificity_score * self.weights.specificity
            + security_insight_score * self.weights.security_insight
            + response_time_score * self.weights.response_time
            + efficiency_score * self.weights.efficiency
        )

        # Generate explanation
        explanation = self._generate_explanation(
            correctness_score,
            completeness_score,
            specificity_score,
            security_insight_score,
            response_time_score,
            efficiency_score,
            total_score,
        )

        return RewardBreakdown(
            correctness_score=correctness_score,
            completeness_score=completeness_score,
            specificity_score=specificity_score,
            security_insight_score=security_insight_score,
            response_time_score=response_time_score,
            efficiency_score=efficiency_score,
            total_score=total_score,
            explanation=explanation,
        )

    def _calculate_correctness_score(self, correctness_eval: Dict[str, Any]) -> float:
        """Calculate correctness component score.

        Args:
            correctness_eval: Correctness evaluation from judge

        Returns:
            Correctness score (0-1)
        """
        if not correctness_eval:
            return 0.0

        # Base score from acceptance
        base_score = 1.0 if correctness_eval.get("accept", False) else 0.0

        # Weight by confidence
        confidence = correctness_eval.get("confidence", 0.5)
        weighted_score = base_score * confidence

        # Penalties for incorrect/missing information
        incorrect_info = correctness_eval.get("incorrect_info", [])
        missing_info = correctness_eval.get("missing_info", [])

        penalty = len(incorrect_info) * 0.2 + len(missing_info) * 0.1

        return max(0.0, weighted_score - penalty)

    def _calculate_completeness_score(self, correctness_eval: Dict[str, Any]) -> float:
        """Calculate completeness component score.

        Args:
            correctness_eval: Correctness evaluation from judge

        Returns:
            Completeness score (0-1)
        """
        if not correctness_eval:
            return 0.0

        # Base score from acceptance
        base_score = 1.0 if correctness_eval.get("accept", False) else 0.5

        # Penalty for missing information
        missing_info = correctness_eval.get("missing_info", [])
        if missing_info:
            penalty = min(0.8, len(missing_info) * 0.2)
            base_score = max(0.0, base_score - penalty)

        return base_score

    def _calculate_specificity_score(
        self, correctness_eval: Dict[str, Any], question_type: str
    ) -> float:
        """Calculate specificity component score.

        Args:
            correctness_eval: Correctness evaluation from judge
            question_type: Type of question being answered

        Returns:
            Specificity score (0-1)
        """
        # Questions requiring high specificity
        high_specificity_types = {"services", "errors", "access", "users"}
        requires_high_specificity = question_type in high_specificity_types

        if not correctness_eval:
            return 0.0

        # Base score from correctness
        base_score = 0.8 if correctness_eval.get("accept", False) else 0.2

        # Bonus for high specificity questions that are answered correctly
        if requires_high_specificity and correctness_eval.get("accept", False):
            base_score = min(1.0, base_score + 0.2)

        return base_score

    def _calculate_security_insight_score(
        self, correctness_eval: Dict[str, Any], question_type: str
    ) -> float:
        """Calculate security insight component score.

        Args:
            correctness_eval: Correctness evaluation from judge
            question_type: Type of question being answered

        Returns:
            Security insight score (0-1)
        """
        # Security-focused question types get higher weight
        security_types = {"errors", "access", "users", "suspicious"}
        is_security_focused = question_type in security_types

        # Base score from correctness (security insight correlated with accuracy)
        base_score = 0.8 if correctness_eval.get("accept", False) else 0.3

        # Bonus for security-focused questions that are answered correctly
        if is_security_focused and correctness_eval.get("accept", False):
            base_score = min(1.0, base_score + 0.2)

        return base_score

    def _calculate_response_time_score(
        self, response_time: float, difficulty: str
    ) -> float:
        """Calculate response time component score.

        Args:
            response_time: Time taken to respond (seconds)
            difficulty: Difficulty level of the question

        Returns:
            Response time score (0-1)
        """
        # Define target response times by difficulty
        target_times = {
            "easy": 15.0,  # 15 seconds
            "medium": 30.0,  # 30 seconds
            "hard": 60.0,  # 60 seconds
        }

        target_time = target_times.get(difficulty, 30.0)

        # Score based on how close to target time
        if response_time <= target_time:
            return 1.0
        elif response_time <= target_time * 2:
            # Linear decay for times up to 2x target
            return 1.0 - (response_time - target_time) / target_time
        else:
            # Minimum score for very slow responses
            return 0.1

    def _calculate_efficiency_score(
        self, agent_metrics: Dict[str, Any], difficulty: str
    ) -> float:
        """Calculate efficiency component score based on tool usage and reasoning cycles.

        Args:
            agent_metrics: Agent execution metrics (tool calls, cycles, etc.)
            difficulty: Difficulty level of the question

        Returns:
            Efficiency score (0-1)
        """
        # Extract metrics with defaults
        reasoning_cycles = agent_metrics.get("reasoning", {}).get("cycles", 1)
        tool_calls = agent_metrics.get("tools", {}).get("total_calls", 1)
        tools_per_cycle = agent_metrics.get("tools", {}).get("calls_per_cycle", 1.0)

        # Define efficiency targets by difficulty
        efficiency_targets = {
            "easy": {"max_cycles": 2, "max_tools": 3, "max_tools_per_cycle": 2.0},
            "medium": {"max_cycles": 4, "max_tools": 6, "max_tools_per_cycle": 2.5},
            "hard": {"max_cycles": 6, "max_tools": 10, "max_tools_per_cycle": 3.0}
        }

        targets = efficiency_targets.get(difficulty, efficiency_targets["medium"])

        # Score reasoning cycles efficiency (fewer cycles = better)
        cycle_score = min(1.0, targets["max_cycles"] / max(1, reasoning_cycles))

        # Score tool usage efficiency (fewer tools = better, but not zero)
        tool_score = min(1.0, targets["max_tools"] / max(1, tool_calls))

        # Score tools per cycle efficiency (consistent tool usage per cycle)
        tools_per_cycle_score = min(1.0, targets["max_tools_per_cycle"] / max(0.1, tools_per_cycle))

        # Combined efficiency score
        efficiency_score = (
            cycle_score * 0.4 +
            tool_score * 0.4 +
            tools_per_cycle_score * 0.2
        )

        return efficiency_score

    def _generate_explanation(
        self,
        correctness: float,
        completeness: float,
        specificity: float,
        security_insight: float,
        response_time: float,
        efficiency: float,
        total: float,
    ) -> str:
        """Generate explanation of reward score.

        Args:
            correctness: Correctness score
            completeness: Completeness score
            specificity: Specificity score
            security_insight: Security insight score
            response_time: Response time score
            efficiency: Efficiency score
            total: Total score

        Returns:
            Explanation string
        """
        explanations = []

        if correctness >= 0.8:
            explanations.append("Strong factual accuracy")
        elif correctness >= 0.5:
            explanations.append("Moderate accuracy with some issues")
        else:
            explanations.append("Poor accuracy, significant errors")

        if completeness >= 0.8:
            explanations.append("comprehensive coverage")
        elif completeness >= 0.5:
            explanations.append("adequate coverage with minor gaps")
        else:
            explanations.append("incomplete answer")

        if specificity >= 0.8:
            explanations.append("high specificity")
        elif specificity >= 0.5:
            explanations.append("moderate specificity")
        else:
            explanations.append("lacking specific details")

        if security_insight >= 0.8:
            explanations.append("excellent security insights")
        elif security_insight >= 0.5:
            explanations.append("good security context")
        else:
            explanations.append("limited security analysis")

        if response_time >= 0.8:
            explanations.append("efficient response time")
        elif response_time >= 0.5:
            explanations.append("acceptable response time")
        else:
            explanations.append("slow response time")

        if efficiency >= 0.8:
            explanations.append("excellent reasoning efficiency")
        elif efficiency >= 0.5:
            explanations.append("moderate reasoning efficiency")
        else:
            explanations.append("inefficient reasoning patterns")

        return f"Total score: {total:.3f}. " + ", ".join(explanations) + "."


# Utility functions for different reward profiles
def create_accuracy_focused_weights() -> RewardWeights:
    """Create weights that prioritize accuracy over other factors."""
    return RewardWeights(
        correctness=0.6,
        completeness=0.2,
        specificity=0.1,
        security_insight=0.05,
        response_time=0.03,
        efficiency=0.02,
    )


def create_speed_focused_weights() -> RewardWeights:
    """Create weights that balance accuracy with speed."""
    return RewardWeights(
        correctness=0.35,
        completeness=0.15,
        specificity=0.1,
        security_insight=0.1,
        response_time=0.2,
        efficiency=0.1,
    )


def create_security_focused_weights() -> RewardWeights:
    """Create weights that prioritize security insights."""
    return RewardWeights(
        correctness=0.25,
        completeness=0.2,
        specificity=0.15,
        security_insight=0.3,
        response_time=0.05,
        efficiency=0.05,
    )


# Example usage
if __name__ == "__main__":
    # Test reward function
    reward_fn = CloudTrailRewardFunction()

    # Mock evaluation data
    mock_evaluation = {
        "correctness": {
            "accept": True,
            "confidence": 0.9,
            "missing_info": [],
            "incorrect_info": [],
        }
    }

    result = reward_fn.calculate_reward(
        evaluation=mock_evaluation,
        response_time=12.5,
        question_type="errors",
        difficulty="medium",
    )

    print("Reward Breakdown:")
    print(f"Correctness: {result.correctness_score:.3f}")
    print(f"Completeness: {result.completeness_score:.3f}")
    print(f"Specificity: {result.specificity_score:.3f}")
    print(f"Security Insight: {result.security_insight_score:.3f}")
    print(f"Response Time: {result.response_time_score:.3f}")
    print(f"Total Score: {result.total_score:.3f}")
    print(f"Explanation: {result.explanation}")
