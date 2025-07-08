"""Analyze reward component correlations from benchmark results."""

import json
from pathlib import Path
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def load_benchmark_results(results_file: str) -> List[Dict[str, Any]]:
    """Load benchmark results from JSON file.
    
    Args:
        results_file: Path to benchmark results JSON file
        
    Returns:
        List of benchmark results
    """
    with open(results_file, 'r') as f:
        return json.load(f)


def create_analysis_dataframe(results: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert benchmark results to pandas DataFrame for analysis.
    
    Args:
        results: List of benchmark results
        
    Returns:
        DataFrame with relevant columns for analysis
    """
    data = []
    
    for result in results:
        if not result.get('success', False):
            continue
            
        evaluation = result.get('evaluation', {})
        correctness = evaluation.get('correctness', {})
        reward = evaluation.get('reward', {})
        
        row = {
            # Judge evaluation
            'judge_accept': correctness.get('accept', False),
            'judge_confidence': correctness.get('confidence', 0.0),
            'missing_info_count': len(correctness.get('missing_info', [])),
            'incorrect_info_count': len(correctness.get('incorrect_info', [])),
            
            # Reward components
            'correctness_score': reward.get('correctness_score', 0.0),
            'completeness_score': reward.get('completeness_score', 0.0),
            'specificity_score': reward.get('specificity_score', 0.0),
            'security_insight_score': reward.get('security_insight_score', 0.0),
            'response_time_score': reward.get('response_time_score', 0.0),
            'total_score': reward.get('total_score', 0.0),
            
            # Question metadata
            'question_type': result.get('question_type', ''),
            'difficulty': result.get('difficulty', ''),
            'response_time': result.get('response_time', 0.0),
            
            # Overall performance
            'overall_score': evaluation.get('overall_score', 0.0)
        }
        data.append(row)
    
    return pd.DataFrame(data)


def analyze_component_correlations(df: pd.DataFrame) -> pd.DataFrame:
    """Analyze correlations between reward components and judge evaluation.
    
    Args:
        df: DataFrame with benchmark results
        
    Returns:
        Correlation matrix
    """
    # Select numeric columns for correlation analysis
    numeric_cols = [
        'judge_confidence', 'missing_info_count', 'incorrect_info_count',
        'correctness_score', 'completeness_score', 'specificity_score',
        'security_insight_score', 'response_time_score', 'total_score',
        'response_time', 'overall_score'
    ]
    
    return df[numeric_cols].corr()


def analyze_by_question_type(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Analyze component performance by question type.
    
    Args:
        df: DataFrame with benchmark results
        
    Returns:
        Dictionary with analysis by question type
    """
    analysis = {}
    
    for qtype in df['question_type'].unique():
        type_df = df[df['question_type'] == qtype]
        
        component_cols = [
            'correctness_score', 'completeness_score', 'specificity_score',
            'security_insight_score', 'response_time_score'
        ]
        
        stats = type_df[component_cols].describe()
        analysis[qtype] = stats
    
    return analysis


def analyze_by_difficulty(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Analyze component performance by difficulty level.
    
    Args:
        df: DataFrame with benchmark results
        
    Returns:
        Dictionary with analysis by difficulty
    """
    analysis = {}
    
    for difficulty in df['difficulty'].unique():
        diff_df = df[df['difficulty'] == difficulty]
        
        component_cols = [
            'correctness_score', 'completeness_score', 'specificity_score',
            'security_insight_score', 'response_time_score'
        ]
        
        stats = diff_df[component_cols].describe()
        analysis[difficulty] = stats
    
    return analysis


def suggest_optimal_weights(df: pd.DataFrame) -> Dict[str, float]:
    """Suggest optimal weights based on correlation with judge acceptance.
    
    Args:
        df: DataFrame with benchmark results
        
    Returns:
        Dictionary with suggested weights
    """
    # Calculate correlations with judge acceptance
    component_cols = [
        'correctness_score', 'completeness_score', 'specificity_score',
        'security_insight_score', 'response_time_score'
    ]
    
    correlations = {}
    for col in component_cols:
        corr = df[col].corr(df['judge_accept'])
        correlations[col.replace('_score', '')] = abs(corr)  # Use absolute correlation
    
    # Normalize to sum to 1.0
    total_corr = sum(correlations.values())
    if total_corr > 0:
        weights = {k: v / total_corr for k, v in correlations.items()}
    else:
        # Fallback to equal weights
        weights = {k: 0.2 for k in correlations.keys()}
    
    return weights


def generate_analysis_report(
    df: pd.DataFrame,
    output_dir: str = "component_analysis"
) -> None:
    """Generate comprehensive analysis report.
    
    Args:
        df: DataFrame with benchmark results
        output_dir: Directory to save analysis results
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Correlation analysis
    correlations = analyze_component_correlations(df)
    
    # Analysis by question type and difficulty
    by_type = analyze_by_question_type(df)
    by_difficulty = analyze_by_difficulty(df)
    
    # Optimal weights suggestion
    optimal_weights = suggest_optimal_weights(df)
    
    # Generate report
    report_file = output_path / "component_analysis_report.md"
    with open(report_file, 'w') as f:
        f.write("# Reward Component Analysis Report\n\n")
        
        # Basic statistics
        f.write("## Dataset Overview\n\n")
        f.write(f"- Total successful evaluations: {len(df)}\n")
        f.write(f"- Judge acceptance rate: {df['judge_accept'].mean():.2%}\n")
        f.write(f"- Average judge confidence: {df['judge_confidence'].mean():.3f}\n")
        f.write(f"- Average response time: {df['response_time'].mean():.2f}s\n\n")
        
        # Component correlations
        f.write("## Component Correlations with Judge Acceptance\n\n")
        judge_corrs = correlations['judge_accept'].drop('judge_accept').sort_values(ascending=False)
        for component, corr in judge_corrs.items():
            f.write(f"- **{component}**: {corr:.3f}\n")
        f.write("\n")
        
        # Suggested optimal weights
        f.write("## Suggested Optimal Weights\n\n")
        f.write("Based on correlation with judge acceptance:\n\n")
        for component, weight in optimal_weights.items():
            f.write(f"- **{component}**: {weight:.3f} ({weight*100:.1f}%)\n")
        f.write("\n")
        
        # Performance by question type
        f.write("## Performance by Question Type\n\n")
        for qtype, stats in by_type.items():
            f.write(f"### {qtype}\n\n")
            avg_scores = stats.loc['mean']
            for component, score in avg_scores.items():
                f.write(f"- {component}: {score:.3f}\n")
            f.write("\n")
        
        # Performance by difficulty
        f.write("## Performance by Difficulty\n\n")
        for difficulty, stats in by_difficulty.items():
            f.write(f"### {difficulty}\n\n")
            avg_scores = stats.loc['mean']
            for component, score in avg_scores.items():
                f.write(f"- {component}: {score:.3f}\n")
            f.write("\n")
    
    # Save correlation matrix
    correlations.to_csv(output_path / "correlations.csv")
    
    # Save suggested weights as JSON
    with open(output_path / "suggested_weights.json", 'w') as f:
        json.dump(optimal_weights, f, indent=2)
    
    print(f"Analysis report saved to {report_file}")
    print(f"Suggested weights: {optimal_weights}")


def plot_component_analysis(df: pd.DataFrame, output_dir: str = "component_analysis") -> None:
    """Generate visualization plots for component analysis.
    
    Args:
        df: DataFrame with benchmark results
        output_dir: Directory to save plots
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Set up the plotting style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # 1. Correlation heatmap
    fig, ax = plt.subplots(figsize=(12, 10))
    correlations = analyze_component_correlations(df)
    sns.heatmap(correlations, annot=True, cmap='coolwarm', center=0, ax=ax)
    plt.title('Reward Component Correlations')
    plt.tight_layout()
    plt.savefig(output_path / "correlation_heatmap.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Component scores distribution
    component_cols = [
        'correctness_score', 'completeness_score', 'specificity_score',
        'security_insight_score', 'response_time_score'
    ]
    
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    axes = axes.flatten()
    
    for i, col in enumerate(component_cols):
        df[col].hist(bins=20, ax=axes[i], alpha=0.7)
        axes[i].set_title(col.replace('_', ' ').title())
        axes[i].set_xlabel('Score')
        axes[i].set_ylabel('Frequency')
    
    # Remove empty subplot
    axes[-1].remove()
    
    plt.tight_layout()
    plt.savefig(output_path / "component_distributions.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # 3. Performance by question type
    fig, ax = plt.subplots(figsize=(12, 8))
    type_means = df.groupby('question_type')[component_cols].mean()
    type_means.plot(kind='bar', ax=ax)
    plt.title('Average Component Scores by Question Type')
    plt.xlabel('Question Type')
    plt.ylabel('Average Score')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(output_path / "performance_by_type.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Plots saved to {output_path}")


# Main analysis function
def analyze_benchmark_results(results_file: str, output_dir: str = "component_analysis"):
    """Main function to analyze benchmark results.
    
    Args:
        results_file: Path to benchmark results JSON file
        output_dir: Directory to save analysis outputs
    """
    print(f"Loading results from {results_file}...")
    results = load_benchmark_results(results_file)
    
    print("Converting to DataFrame...")
    df = create_analysis_dataframe(results)
    
    if len(df) == 0:
        print("No successful results found in the benchmark data.")
        return
    
    print(f"Analyzing {len(df)} successful results...")
    
    # Generate analysis report
    generate_analysis_report(df, output_dir)
    
    # Generate plots
    try:
        plot_component_analysis(df, output_dir)
    except ImportError:
        print("Matplotlib/Seaborn not available. Skipping plots.")
    
    print("Analysis complete!")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python analyze_components.py <benchmark_results.json>")
        sys.exit(1)
    
    results_file = sys.argv[1]
    analyze_benchmark_results(results_file)