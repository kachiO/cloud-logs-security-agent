"""LLM Judge for evaluating CloudTrail agent responses against ground truth."""

import logging
from dataclasses import dataclass
from typing import Any, Dict

import litellm
from litellm.caching.caching import Cache, LiteLLMCacheType
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt

logger = logging.getLogger(__name__)

# Setup caching for LLM calls
litellm.cache = Cache(type=LiteLLMCacheType.DISK)


class CorrectnessJudgeResponse(BaseModel):
    """Response from the correctness judge."""

    reasoning: str = Field(description="Explanation of the reasoning process")
    accept: bool = Field(description="Whether the AI answer should be accepted")
    confidence: float = Field(description="Confidence score (0-1)", ge=0, le=1)
    missing_info: list[str] = Field(
        description="List of missing information if any", default_factory=list
    )
    incorrect_info: list[str] = Field(
        description="List of incorrect information if any", default_factory=list
    )


@dataclass
class CloudTrailQuestion:
    """CloudTrail question and answer pair."""

    question: str
    answer: str
    question_type: str
    difficulty: str
    time_range: str
    relevant_events: str
    partition: str


@retry(stop=stop_after_attempt(3))
async def judge_correctness(
    question_data: CloudTrailQuestion, agent_answer: str, model: str = "openai/gpt-4o"
) -> CorrectnessJudgeResponse:
    """Judge the correctness of an agent's answer against ground truth.

    Args:
        question_data: The question and ground truth answer
        agent_answer: The agent's response to evaluate
        model: LLM model to use for judging

    Returns:
        Judgment result with reasoning and decision
    """
    system_prompt = """You are an expert evaluator for CloudTrail security analysis responses. Your task is to judge whether an AI agent's answer is correct compared to the ground truth reference answer.

Evaluation Criteria:
1. **Factual Accuracy**: Are the facts, numbers, and specific details correct?
2. **Completeness**: Does the answer address all aspects of the question?
3. **Relevance**: Is the information relevant to the security question asked?
4. **Specificity**: Are specific events, IPs, services, or time periods mentioned when required?

For CloudTrail security analysis, pay special attention to:
- Event counts and statistics
- Service names (e.g., ec2.amazonaws.com, iam.amazonaws.com)
- IP addresses and network information
- Error codes and types
- Time ranges and patterns
- User identity information
- Security implications

Accept the answer if:
- Core facts match the reference answer (minor formatting differences OK)
- All key security information is present
- The answer demonstrates understanding of the security context
- Specific numbers/counts are accurate (within reasonable margin for approximations)

Reject the answer if:
- Key facts are missing or incorrect
- Wrong event counts or statistics
- Incorrect service names or IP addresses
- Missing critical security insights
- Answer is too vague when specificity is required"""

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": f"""Question: {question_data.question}

Question Type: {question_data.question_type}
Difficulty: {question_data.difficulty}
Time Range: {question_data.time_range}
Relevant Events: {question_data.relevant_events}

Reference Answer: {question_data.answer}

AI Agent Answer: {agent_answer}

Please evaluate the AI agent's answer against the reference answer and provide your judgment.""",
        },
    ]

    try:
        response = await litellm.acompletion(
            model=model,
            messages=messages,
            caching=True,
            response_format=CorrectnessJudgeResponse,
            temperature=0.1,  # Low temperature for consistent evaluation
        )

        first_choice = response.choices[0]
        raw_content = first_choice.message.content or "{}"

        return CorrectnessJudgeResponse.model_validate_json(raw_content)

    except Exception as e:
        logger.error(f"Judge evaluation failed: {e}")
        # Return conservative judgment on failure
        return CorrectnessJudgeResponse(
            reasoning=f"Evaluation failed due to error: {str(e)}",
            accept=False,
            confidence=0.0,
            missing_info=["Unable to evaluate due to error"],
            incorrect_info=[],
        )


class CloudTrailJudge:
    """CloudTrail response judge for evaluating agent performance."""

    def __init__(self, model: str = "openai/gpt-4o"):
        """Initialize the judge.

        Args:
            model: LLM model to use for evaluation
        """
        self.model = model

    async def evaluate_response(
        self, question_data: CloudTrailQuestion, agent_answer: str
    ) -> Dict[str, Any]:
        """Evaluate an agent's response for correctness.

        Args:
            question_data: Question and ground truth data
            agent_answer: Agent's response to evaluate

        Returns:
            Evaluation results
        """
        # Correctness evaluation
        correctness = await judge_correctness(question_data, agent_answer, self.model)

        # Overall score based on correctness
        overall_score = self._calculate_overall_score(correctness)

        return {"correctness": correctness.model_dump(), "overall_score": overall_score}

    def _calculate_overall_score(self, correctness: CorrectnessJudgeResponse) -> float:
        """Calculate overall score from correctness evaluation.

        Args:
            correctness: Correctness evaluation result

        Returns:
            Overall score (0-1)
        """
        # Base score from correctness
        base_score = 1.0 if correctness.accept else 0.0

        # Weight by confidence
        weighted_score = base_score * correctness.confidence

        # Additional penalty for missing/incorrect info
        penalty = 0.0
        if correctness.missing_info:
            penalty += len(correctness.missing_info) * 0.1
        if correctness.incorrect_info:
            penalty += len(correctness.incorrect_info) * 0.15

        final_score = max(0.0, weighted_score - penalty)

        return min(1.0, final_score)


# Example usage
if __name__ == "__main__":
    import asyncio

    # Test data
    test_question = CloudTrailQuestion(
        question="What is the total number of CloudTrail events recorded between 2018-11-01 and 2019-01-27?",
        answer="The total number of CloudTrail events recorded in the given date range is 23054.",
        question_type="overview",
        difficulty="easy",
        time_range="['2018-11-01', '2019-01-27']",
        relevant_events="null",
        partition="customer_201811_201901_questions",
    )

    test_agent_answer = "There are 23,054 CloudTrail events recorded between November 1, 2018 and January 27, 2019."

    async def test_judge():
        judge = CloudTrailJudge()
        result = await judge.evaluate_response(test_question, test_agent_answer)
        print("Evaluation Result:")
        print(result)

    asyncio.run(test_judge())
