═══════════════════════════════════════════════════════════════════════════════
CLAWSTRIKE — TRAINING DATA PIPELINE SCRIPTS
═══════════════════════════════════════════════════════════════════════════════

This folder contains all scripts for building ClawStrike's training dataset.
The pipeline converts raw pentesting writeups into structured JSONL training
examples for fine-tuning Qwen2.5 72B.


═══════════════════════════════════════════════════════════════════════════════
SETUP
═══════════════════════════════════════════════════════════════════════════════

Before running any script:

  1. Activate the virtual environment:
     source ~/clawstrike-env/bin/activate

  2. Set your API key:
     export ANTHROPIC_API_KEY=your_key_here

  3. Make sure dependencies are installed:
     pip install anthropic rich requests beautifulsoup4


═══════════════════════════════════════════════════════════════════════════════
PIPELINE OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

The data flows through three stages:

  STAGE 1: FETCH (writeup_fetcher.py)
  Writeup URL → fetches page → AI extracts layer-specific content → raw .txt

  STAGE 2: EXTRACT (writeup_extractor.py)
  Raw .txt → Claude extracts structured JSON dict → human review → approved

  STAGE 3: CONVERT (layer1_converter.py)
  Approved JSON dict → JSONL training examples → appended to dataset

  STAGE 1.5: VALIDATE (quality_check.py)
  Raw .txt → automated quality checks per layer → PASS/FAIL verdict

  Full flow:
  URL → writeup_fetcher.py → raw .txt → quality_check.py → PASS?
  → writeup_extractor.py → review → layer1_converter.py → processed JSONL


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 1: writeup_fetcher.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Fetches pentesting writeups from any URL and formats them into raw data
  files organized by training layer. Designed for delegation — juniors run
  this, leads review the output.

USAGE:
  python scripts/writeup_fetcher.py <links_file> [--layer N] [--no-ai]

ARGUMENTS:
  links_file    Text file with one URL per line (lines starting with # are
                skipped)
  --layer N     Which training layer to format for (1-7, default: 1)
  --no-ai       Skip AI extraction, save raw page text only

LAYER OPTIONS:
  --layer 1     Recon decision trees (what to do after seeing scan results)
  --layer 2     Tool output parsing (extract findings from raw tool output)
  --layer 3     Failed paths + pivots (what failed, why, what next)
  --layer 4     Exploit ranking (prioritize vulnerabilities by probability)
  --layer 5     Post-exploitation reasoning (privesc, creds, lateral movement)
  --layer 6     Reporting intelligence (convert evidence to findings)
  --layer 7     Ethics + scope enforcement (trained refusals)

EXAMPLES:

  # Create a links file
  nano ~/clawstrike-data/links/htb_easy.txt
  # Add URLs, one per line:
  #   https://0xdf.gitlab.io/2020/04/07/htb-lame.html
  #   https://0xdf.gitlab.io/2021/05/11/htb-blue.html

  # Fetch recon data (Layer 1)
  cd ~/clawstrike-data
  ANTHROPIC_API_KEY=sk-... python scripts/writeup_fetcher.py links/htb_easy.txt --layer 1

  # Fetch failure/pivot data (Layer 3) from same URLs
  ANTHROPIC_API_KEY=sk-... python scripts/writeup_fetcher.py links/htb_easy.txt --layer 3

  # Fetch without AI (raw page content only)
  python scripts/writeup_fetcher.py links/htb_easy.txt --layer 1 --no-ai

OUTPUT:
  Raw .txt files saved to ~/clawstrike-data/raw/<source>/
  Metadata logged to ~/clawstrike-data/metadata/fetch_tracker.jsonl

NOTES:
  - The script rate-limits itself (2 second delay between URLs)
  - Works with any URL (0xdf, rana-khalil, medium, hacktricks, etc.)
  - Same URL can be fetched multiple times with different --layer flags
  - Each layer extracts different content from the same writeup
  - If no API key is set, saves raw text for manual extraction


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 2: quality_check.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Validates raw writeup files against training data quality standards.
  Gives a PASS/FAIL verdict with specific issues flagged. Run this BEFORE
  feeding files into writeup_extractor.py to catch bad data early.
  No API key needed — runs entirely offline using pattern matching.

USAGE:
  python scripts/quality_check.py <file_or_directory> [--layer N] [--strict]

ARGUMENTS:
  file_or_directory   Single .txt file or directory of .txt/.md files
  --layer N           Which layer's standards to check against (1-7, default: 1)
  --strict            Treat warnings as failures (use for final dataset)

EXAMPLES:

  # Check a single file
  cd ~/clawstrike-data
  python scripts/quality_check.py raw/htb/blue.txt --layer 1

  # Check all files in a directory
  python scripts/quality_check.py raw/htb/ --layer 1

  # Strict mode — warnings become failures
  python scripts/quality_check.py raw/htb/ --layer 1 --strict

  # Check Layer 3 (failed paths) data
  python scripts/quality_check.py raw/failures/ --layer 3

  # Check Layer 5 (post-exploitation) data
  python scripts/quality_check.py raw/post_exploit/ --layer 5

WHAT IT CHECKS (Layer 1 — Recon Decision Trees):
  REQUIRED (must pass):
    ✓ Raw scan output present (nmap results with port/service data)
    ✓ Service versions included (version numbers for exploit reasoning)
    ✓ Decision reasoning present (WHY decisions were made)

  FORBIDDEN (auto-fail):
    ✗ Study-guide summaries (KEY FINDINGS, CRITICAL VECTORS)

  SHOULD HAVE (warnings, failures in strict mode):
    ⚠ Multiple ports/services (needed for prioritization logic)
    ⚠ Real commands shown (nmap, gobuster, smbclient, etc.)
    ⚠ Fallback or alternative paths mentioned

  SIZE:
    ✗ Too short: under 200 words
    ⚠ Very long: over 8000 words

WHAT IT CHECKS (other layers):
  Each layer has its own checks. Examples:
    Layer 2: requires raw tool output + tool identification
    Layer 3: requires failure description + recovery/pivot action
    Layer 4: requires multiple vulnerabilities + prioritization reasoning
    Layer 5: requires shell context + privilege escalation content
    Layer 6: requires vulnerability findings + evidence
    Layer 7: requires scope/authorization context

OUTPUT:
  Prints PASS/FAIL verdict per file with specific issues flagged.
  When checking a directory, prints a summary at the end.

  ✅ PASS          — file meets all quality standards
  ⚠️  PASS (warnings) — meets required standards but missing nice-to-haves
  ❌ FAIL          — file does not meet required standards, needs fixing

NOTES:
  - No API key needed — runs entirely offline
  - Run this BEFORE writeup_extractor.py to save API tokens on bad files
  - Use --strict for final dataset validation
  - Juniors can run this to self-check their fetcher output before handoff


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 3: writeup_extractor.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Takes raw writeup text files and uses Claude API to extract structured
  training data. Presents the extraction for human review before saving.
  This is the quality gate — nothing enters the dataset without approval.

USAGE:
  python scripts/writeup_extractor.py <path>

ARGUMENTS:
  path          Single .txt file or directory of .txt/.md files

EXAMPLES:

  # Process a single writeup
  cd ~/clawstrike-data
  ANTHROPIC_API_KEY=sk-... python scripts/writeup_extractor.py raw/htb/lame.txt

  # Process all writeups in a directory
  ANTHROPIC_API_KEY=sk-... python scripts/writeup_extractor.py raw/htb/

REVIEW OPTIONS:
  When the extraction is shown, you choose:
    [a] approve  — generates training examples and saves to processed/
    [e] edit     — saves JSON for manual editing, prints edit instructions
    [s] skip     — discards this extraction, moves to next file

OUTPUT:
  Approved extractions → ~/clawstrike-data/processed/layer1_recon/<boxname>.jsonl
  Edited extractions   → ~/clawstrike-data/raw/<boxname>_extracted.json
  Metadata             → ~/clawstrike-data/metadata/layer1_tracker.jsonl

NOTES:
  - Uses claude-sonnet-4-20250514 for extraction (cost effective, good quality)
  - Each box generates 1-3 training examples depending on content:
      1. Initial scan → first decision
      2. Pivot point (if present)
      3. Failed attempt recovery (if present)
  - Always review before approving — Claude can misinterpret writeups
  - If you choose [e]dit, modify the JSON file then run load_edited.py


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 4: layer1_converter.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Converts structured box dictionaries into JSONL training examples.
  Called automatically by writeup_extractor.py on approval, but can also
  be used standalone for manual data entry.

USAGE:
  python scripts/layer1_converter.py

  (Run directly to process the built-in LAME example template)

STANDALONE USE:
  Edit the script to add new box templates (copy the LAME dict format),
  then run. Useful when you want to manually create training data without
  going through the extractor.

TEMPLATE FORMAT:
  Each box needs:
    box_name      - name of the machine
    target        - IP address
    source        - writeup author/blog
    difficulty    - easy/medium/hard/insane
    ports         - list of {port, proto, service, version}
    priorities    - list of {service, reasoning} ranked by exploit probability
    first_action  - what to do first
    fallback      - backup plan
    avoid         - what NOT to do and why
    pivot_point   - (optional) result of first action + next decision
    failed_attempt - (optional) what failed + why + recovery

OUTPUT:
  Training examples → ~/clawstrike-data/processed/layer1_recon/<boxname>.jsonl
  Metadata          → ~/clawstrike-data/metadata/layer1_tracker.jsonl

EXAMPLE OUTPUT FORMAT (one line per example in JSONL):
  {
    instruction: You are a penetration tester...nOpen ports:n- 21/tcp FTP...,
    output: Thought: Analyzing services...n1. FTP vsftpd 2.3.4...nAction: ...,
    metadata: {layer: layer1_recon, box_name: Lame, ...}
  }


═══════════════════════════════════════════════════════════════════════════════
DIRECTORY STRUCTURE
═══════════════════════════════════════════════════════════════════════════════

~/clawstrike-data/
├── raw/                          ← Untouched source material
│   ├── htb/                      ← HTB writeup raw text (Layer 1 default)
│   ├── thm/                      ← TryHackMe writeups
│   ├── vulnhub/                  ← VulnHub writeups
│   ├── tool_outputs/             ← Raw tool outputs (Layer 2)
│   ├── failures/                 ← Failed path narratives (Layer 3)
│   ├── exploit_ranking/          ← Exploit selection reasoning (Layer 4)
│   ├── post_exploit/             ← Post-exploitation narratives (Layer 5)
│   ├── reporting/                ← Vulnerability findings (Layer 6)
│   ├── ethics/                   ← Scope/ethics content (Layer 7)
│   ├── exploitdb/
│   ├── nvd/
│   ├── project-zero/
│   ├── portswigger/
│   └── hacktricks/
│
├── processed/                    ← Cleaned, structured JSONL per layer
│   ├── layer1_recon/             ← Recon decision tree examples
│   ├── layer2_parsing/           ← Tool output parsing examples
│   ├── layer3_failures/          ← Failed path + pivot examples
│   ├── layer4_exploits/          ← Exploit ranking examples
│   ├── layer5_postexploit/       ← Post-exploitation examples
│   ├── layer6_reporting/         ← Report finding examples
│   └── layer7_ethics/            ← Ethics/scope examples
│
├── training/                     ← Final merged JSONL for fine-tuning
│   └── clawstrike_v1.jsonl       ← (created by merge script later)
│
├── eval/                         ← 10% holdout for validation
│   └── clawstrike_eval_v1.jsonl  ← (created by merge script later)
│
├── links/                        ← URL lists for writeup_fetcher.py
│   ├── htb_easy.txt
│   ├── htb_medium.txt
│   └── htb_hard.txt
│
├── scripts/                      ← This folder
│   ├── README.txt                ← You are here
│   ├── writeup_fetcher.py        ← Stage 1: fetch URLs → raw .txt
│   ├── quality_check.py          ← Stage 1.5: validate raw files → PASS/FAIL
│   ├── writeup_extractor.py      ← Stage 2: raw .txt → structured JSON → review
│   └── layer1_converter.py       ← Stage 3: JSON → JSONL training examples
│
└── metadata/                     ← Tracking and logs
    ├── fetch_tracker.jsonl        ← Log of all fetched URLs
    └── layer1_tracker.jsonl       ← Log of all generated Layer 1 examples


═══════════════════════════════════════════════════════════════════════════════
DELEGATION WORKFLOW (FOR JUNIORS)
═══════════════════════════════════════════════════════════════════════════════

Step 1: Get a list of writeup URLs from your lead
        Save them in ~/clawstrike-data/links/batch_name.txt

Step 2: Activate the environment
        source ~/clawstrike-env/bin/activate

Step 3: Set the API key (ask your lead for it)
        export ANTHROPIC_API_KEY=sk-...

Step 4: Run the fetcher with the layer your lead specified
        cd ~/clawstrike-data
        python scripts/writeup_fetcher.py links/batch_name.txt --layer 1

Step 5: Run the quality checker on fetched files
        python scripts/quality_check.py raw/htb/ --layer 1
        Fix or flag any files that show FAIL

Step 6: Hand over the PASSED output files to your lead for review
        Files are in ~/clawstrike-data/raw/htb/ (or the layer-specific folder)

DO NOT:
  - Run writeup_extractor.py (that's the lead's job — quality gate)
  - Modify any files in processed/ or training/
  - Change the --layer flag without checking with your lead
  - Run the same links file twice (check metadata/fetch_tracker.jsonl)


═══════════════════════════════════════════════════════════════════════════════
QUALITY CHECKLIST (FOR LEADS)
═══════════════════════════════════════════════════════════════════════════════

Before approving any extraction, verify:

  □ Does it contain real scan output (not summarized)?
  □ Does the reasoning explain WHY, not just WHAT?
  □ Are service versions included?
  □ Is there a clear first action + fallback?
  □ Does it mention what NOT to do?
  □ Are any CVEs mentioned actually real and correct?
  □ Is this different enough from existing examples? (no duplicates)
  □ Would a junior pentester learn something from reading this?

If any answer is NO → edit or skip, do not approve.


═══════════════════════════════════════════════════════════════════════════════
SCRIPTS TO BE BUILT (FUTURE)
═══════════════════════════════════════════════════════════════════════════════

  layer2_converter.py     ← Tool output → parsed findings examples
  layer3_converter.py     ← Failed paths → failure recovery examples
  layer4_converter.py     ← Vulnerabilities → exploit ranking examples
  layer5_converter.py     ← Post-exploit → privesc reasoning examples
  layer6_converter.py     ← Evidence → report finding examples
  layer7_converter.py     ← Scenarios → scope enforcement examples
  merge_training.py       ← Combines all layers into final training JSONL
  eval_splitter.py        ← Holds out 10% for evaluation set

These will be built as we complete each layer's data collection.


═══════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

No module named anthropic
  → pip install anthropic

No module named requests or No module named bs4
  → pip install requests beautifulsoup4

ANTHROPIC_API_KEY not set
  → export ANTHROPIC_API_KEY=sk-your-key-here

Could not parse Claude response as JSON
  → The writeup format may be unusual. Try --no-ai and extract manually.

No space left on device
  → mkdir -p ~/pip-tmp && export TMPDIR=~/pip-tmp
    Then retry the pip install.

File not found: links/...
  → Make sure you're running from ~/clawstrike-data/
    cd ~/clawstrike-data

Script hangs or takes too long:
  → Check your internet connection
  → Some writeups are very long — the AI extraction takes 10-30 seconds
  → Ctrl+C to cancel, the script saves progress

═══════════════════════════════════════════════════════════════════════════════
