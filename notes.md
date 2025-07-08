# Notes

#TODO:
- [ ] upload the datasets to HuggingFace repo
- [ ] benchmark prompted models. use strands. models: gpt-4.1, claude-4-sonnet, gemini-2.5-pro, o4-mini, ollama-qwen-3-14b, ollama-deepseek-r1-14B

### Synthetic QA data generation
- Batch vs. agentic data generation
- Batch mode generated with `generate_cloudtrail_questions.py`
  - uses GPT-4.1 (nano & mini) models via OpenAI API
- Agentic generated via Claude Desktop app with motherduck-duckdb MCP (data/flaws_cloudtrail_master-partitions_questions/claude-4-opus-agent)

### Partitions
Create partitions for the CloudTrail data.
```bash
(cloud-logs-security-agent) ➜  cloud-logs-security-agent git:(dev) ✗ uv run validate_partitions.py --partitions-dir data/flaw-partitions

[07/05/25 10:53:13] INFO     Analyzing partition databases in data/flaw-partitions                                                                                                            validate_partitions.py:51
                            CloudTrail Partition Analysis                            
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┓
┃ Partition              ┃   Records ┃ Date Range               ┃ Events ┃ Services ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━┩
│ customer_201702_201704 │    19,096 │ 2017-02-12 to 2017-04-27 │    304 │       42 │
│ customer_201705_201707 │    36,206 │ 2017-05-01 to 2017-07-27 │    209 │       36 │
│ customer_201708_201710 │    15,461 │ 2017-08-01 to 2017-10-27 │    190 │       30 │
│ customer_201711_201801 │    11,090 │ 2017-11-01 to 2018-01-27 │    152 │       28 │
│ customer_201802_201804 │    27,331 │ 2018-02-01 to 2018-04-27 │    169 │       30 │
│ customer_201805_201807 │    12,597 │ 2018-05-01 to 2018-07-27 │    188 │       40 │
│ customer_201808_201810 │    36,321 │ 2018-08-01 to 2018-10-27 │    534 │       92 │
│ customer_201811_201901 │    23,054 │ 2018-11-01 to 2019-01-27 │    421 │       88 │
│ customer_201902_201904 │    43,093 │ 2019-02-01 to 2019-04-27 │    490 │      103 │
│ customer_201905_201906 │    57,478 │ 2019-05-01 to 2019-06-27 │    390 │       78 │
│ customer_201907_201907 │    24,382 │ 2019-07-01 to 2019-07-27 │    623 │      104 │
│ customer_201908_201908 │ 1,345,121 │ 2019-08-01 to 2019-08-27 │    232 │       42 │
│ customer_201909_201911 │    39,862 │ 2019-09-01 to 2019-11-27 │    748 │      118 │
│ customer_201912_202002 │    31,821 │ 2019-12-01 to 2020-02-27 │    705 │      118 │
│ customer_202003_202005 │    50,485 │ 2020-03-01 to 2020-05-27 │    825 │      130 │
│ customer_202006_202008 │    51,802 │ 2020-06-01 to 2020-08-27 │    980 │      151 │
└────────────────────────┴───────────┴──────────────────────────┴────────┴──────────┘
                    INFO     Total records across all partitions: 1,825,200
```


### Analyze High Activity Partition

One of the partitions has a very high number of events, which is `customer_201908_201908.duckdb` with 1,345,121 events. Initially thought about splitting it to smaller partitions, but it seems interesting. 

```bash
(cloud-logs-security-agent) ➜  cloud-logs-security-agent git:(dev) ✗ uv run split_high_activity.py --source-db data/flaw-partitions/customer_201908_201908.duckdb --analyze-only

[07/05/25 15:26:04] INFO     Daily breakdown for customer_201908_201908.duckdb:                                                                                                               split_high_activity.py:30
                    INFO       2019-08-01: 3,002 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-02: 964 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-03: 360 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-04: 130 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-05: 1,648 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-06: 302 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-07: 572 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-08: 220 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-09: 356 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-10: 406 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-11: 2,394 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-12: 654 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-13: 676 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-14: 404 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-15: 438 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-16: 2,276 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-17: 2,342 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-18: 130 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-19: 186 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-20: 3,638 events                                                                                                                                       split_high_activity.py:32
                    INFO       2019-08-21: 531,156 events                                                                                                                                     split_high_activity.py:32
                    INFO       2019-08-22: 554,534 events                                                                                                                                     split_high_activity.py:32
                    INFO       2019-08-23: 237,673 events                                                                                                                                     split_high_activity.py:32
                    INFO       2019-08-24: 127 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-25: 120 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-26: 225 events                                                                                                                                         split_high_activity.py:32
                    INFO       2019-08-27: 188 events      
```