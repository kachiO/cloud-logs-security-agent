#!/usr/bin/env python3
"""
Upload CloudTrail Q&A dataset and DuckDB files to Hugging Face Hub
"""

import json
import logging
from pathlib import Path

from datasets import Dataset
from huggingface_hub import HfApi, create_repo, upload_file, upload_folder
from rich.console import Console
from rich.logging import RichHandler

# Setup rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console)]
)
logger = logging.getLogger(__name__)


def load_jsonl_files(base_path: Path) -> list:
    """Load all JSONL files from partitions_questions directory"""
    data = []

    for model_dir in base_path.iterdir():
        if model_dir.is_dir():
            model_name = model_dir.name
            for jsonl_file in model_dir.glob("*.jsonl"):
                partition_name = jsonl_file.stem
                with open(jsonl_file, "r") as f:
                    for line in f:
                        if line.strip():
                            question_data = json.loads(line)
                            # Ensure all fields are strings or None to avoid type conflicts
                            question_data["model"] = model_name
                            question_data["partition"] = partition_name
                            # Convert time_range to string if it's a list
                            if isinstance(question_data.get("time_range"), list):
                                question_data["time_range"] = str(
                                    question_data["time_range"]
                                )
                            # Convert relevant_events to string if it's a list, or None if empty
                            if isinstance(question_data.get("relevant_events"), list):
                                if question_data["relevant_events"]:
                                    question_data["relevant_events"] = str(
                                        question_data["relevant_events"]
                                    )
                                else:
                                    question_data["relevant_events"] = None
                            # Ensure how_realistic is float
                            if "how_realistic" in question_data:
                                question_data["how_realistic"] = float(
                                    question_data["how_realistic"]
                                )
                            data.append(question_data)

    return data


def create_hf_dataset(data: list) -> Dataset:
    """Create a HuggingFace dataset from the data"""
    # Ensure all data is properly typed
    processed_data = []
    for item in data:
        processed_item = {
            "question": str(item["question"]),
            "answer": str(item["answer"]),
            "question_type": str(item["question_type"]),
            "difficulty": str(item["difficulty"]),
            "time_range": str(item["time_range"]),
            "relevant_events": str(item["relevant_events"])
            if item["relevant_events"]
            else None,
            "how_realistic": float(item["how_realistic"]),
            "model": str(item["model"]),
            "partition": str(item["partition"]),
        }
        processed_data.append(processed_item)

    return Dataset.from_list(processed_data)


def upload_duckdb_files(api: HfApi, repo_id: str, base_path: Path):
    """Upload DuckDB files to the repository"""
    print("Uploading DuckDB files...")

    # Upload master database
    master_db = base_path / "flaws_cloudtrail_master.duckdb"
    if master_db.exists():
        logging.info(f"Uploading {master_db.name}...")
        upload_file(
            path_or_fileobj=str(master_db),
            path_in_repo=f"duckdb/{master_db.name}",
            repo_id=repo_id,
            repo_type="dataset",
        )

    # Upload partition databases
    partitions_dir = base_path / "partitions"
    if partitions_dir.exists():
        logging.info("Uploading partition databases...")
        for db_file in partitions_dir.glob("*.duckdb"):
            logging.info(f"Uploading {db_file.name}...")
            upload_file(
                path_or_fileobj=str(db_file),
                path_in_repo=f"duckdb/partitions/{db_file.name}",
                repo_id=repo_id,
                repo_type="dataset",
            )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Upload CloudTrail Q&A dataset and DuckDB files to Hugging Face Hub"
    )
    parser.add_argument(
        "--base-path",
        type=Path,
        default=Path(
            "data/flaws_cloudtrail_duckdb"
        ),
        help="Base path to the dataset and DuckDB files",
    )
    parser.add_argument(--"username", default="odemzkolo", help="Hugging Face username")
    args = parser.parse_args()
    base_path = Path(args.base_path)
    assert base_path.exists(), f"Error: Base path {base_path} does not exist"
    questions_path = base_path / "partitions_questions"

    if not questions_path.exists():
        logging.error(f"Error: {questions_path} does not exist")
        return

    # Load all JSONL data
    logging.info("Loading JSONL files...")
    data = load_jsonl_files(questions_path)
    logging.info(
        f"Loaded {len(data)} questions from {len(set(item['model'] for item in data))} models"
    )

    # Save data as JSON first
    json_path = base_path/"dataset.json"
    logging.info(f"Saving dataset to {json_path}...")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    # Create HuggingFace dataset
    logging.info("Creating HuggingFace dataset...")
    dataset = create_hf_dataset(data)

    # Skip login if already authenticated
    logging.info("Using existing HuggingFace authentication...")

    # Set up repo details
    dataset_name = "flaws-cloudtrail-security-qa"
    repo_id = f"{args.username}/{dataset_name}"  # Replace with your actual username

    # Create repository
    api = HfApi()
    logging.info(f"Creating repository '{repo_id}'...")
    try:
        create_repo(repo_id=repo_id, repo_type="dataset", exist_ok=True)
    except Exception as e:
        logging.error(f"Repository creation failed: {e}")
        return

    # Upload HuggingFace dataset
    logging.info("Uploading HuggingFace dataset...")
    try:
        dataset.push_to_hub(repo_id, private=False)
        logging.info("HuggingFace dataset uploaded successfully")
    except Exception as e:
        logging.error(f"HuggingFace dataset upload failed: {e}")
        return

    # Upload JSON dataset as backup
    print("Uploading JSON dataset as backup...")
    try:
        upload_file(
            path_or_fileobj=str(json_path),
            path_in_repo="dataset.json",
            repo_id=repo_id,
            repo_type="dataset",
        )
        print("JSON dataset uploaded successfully")
    except Exception as e:
        logging.error(f"JSON dataset upload failed: {e}")
        return

    # Upload DuckDB files
    try:
        upload_duckdb_files(api, repo_id, base_path)
        print("DuckDB files uploaded successfully")
    except Exception as e:
        logging.error(f"DuckDB upload failed: {e}")
        return

    # Upload questions folder structure
    logging.info("Uploading questions folder structure...")
    try:
        upload_folder(
            folder_path=str(questions_path),
            path_in_repo="questions",
            repo_id=repo_id,
            repo_type="dataset",
        )
        logging.info("Questions folder uploaded successfully")
    except Exception as e:
        logging.error(f"Questions folder upload failed: {e}")
        return

    # Upload README
    readme_path = Path("dataset_README.md")
    if readme_path.exists():
        logging.info("Uploading README...")
        try:
            upload_file(
                path_or_fileobj=str(readme_path),
                path_in_repo="README.md",
                repo_id=repo_id,
                repo_type="dataset",
            )
            logging.info("README uploaded successfully")
        except Exception as e:
            logging.error(f"README upload failed: {e}")

    logging.info(f"Dataset uploaded successfully to https://huggingface.co/datasets/{repo_id}")


if __name__ == "__main__":
    main()
