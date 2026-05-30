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

  2. Set your API key (permanent — only do this once):
     echo 'export ANTHROPIC_API_KEY=your_key_here' >> ~/.bashrc
     source ~/.bashrc

  3. Make sure dependencies are installed:
     pip install anthropic rich requests beautifulsoup4


═══════════════════════════════════════════════════════════════════════════════
PIPELINE OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

Three scripts. Always in this order. The --layer flag controls what data
gets extracted.

  STEP 1: FETCH
  Gets writeup content from URLs, extracts only the layer-relevant section,
  saves to raw/{platform}/layer{N}/

  STEP 2: CHECK
  Validates raw files against quality standards. PASS/FAIL verdict.
  No API key needed — runs offline.

  STEP 3: EXTRACT
  Sends raw files to Claude API, converts to structured JSON, you review
  and approve, saves training JSONL to processed/{layer_name}/

  Full flow:
  URL → writeup_fetcher.py → raw .txt → quality_check.py → PASS?
  → writeup_extractor.py → review → training JSONL

  For local files (IppSec transcripts, manual notes):
  Local .txt → local_fetcher.py → raw .txt → quality_check.py → PASS?
  → writeup_extractor.py → review → training JSONL

  For ExploitDB (Layer 4 and 6 only):
  services.txt → exploitdb_fetcher.py → raw .txt → quality_check.py
  → writeup_extractor.py → review → training JSONL


═══════════════════════════════════════════════════════════════════════════════
LAYER FLAGS
═══════════════════════════════════════════════════════════════════════════════

  --layer 1   Recon decision trees (what to do after seeing scan results)
  --layer 2   Tool output parsing (extract findings from raw tool output)
  --layer 3   Failed paths + pivots (what failed, why, what next)
  --layer 4   Exploit ranking (prioritize vulnerabilities by probability)
  --layer 5   Post-exploitation reasoning (privesc, creds, lateral movement)
  --layer 6   Reporting intelligence (convert evidence to findings)
  --layer 7   Ethics + scope enforcement (trained refusals)

  Same URLs can be fetched multiple times with different --layer flags.
  Each run extracts different content from the same writeup.


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 1: writeup_fetcher.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Fetches writeups from URLs, uses AI to extract only layer-relevant content,
  auto-detects platform (HTB/VulnHub/THM), saves to organized directories.
  Handles both HTML pages and raw markdown (GitHub).

USAGE:
  python scripts/writeup_fetcher.py <links_file> [--layer N] [--no-ai]

ARGUMENTS:
  links_file    Text file with one URL per line (# lines are skipped)
  --layer N     Which layer to extract for (1-7, default: 1)
  --no-ai       Save raw content without AI extraction

EXAMPLES:
  # Fetch recon data from VulnHub writeups
  python scripts/writeup_fetcher.py links/vulnhub_links.txt --layer 1

  # Fetch tool output data from same writeups
  python scripts/writeup_fetcher.py links/vulnhub_links.txt --layer 2

  # Fetch failure data from HTB writeups
  python scripts/writeup_fetcher.py links/htb_links.txt --layer 3

OUTPUT:
  raw/{platform}/layer{N}/{boxname}.txt

  Examples:
    raw/vulnhub/layer1/jigsaw.txt
    raw/htb/layer2/lame.txt
    raw/vulnhub/layer3/dc6.txt

NOTES:
  - Auto-detects platform from URL (vulnhub/htb/thm/other)
  - Handles GitHub raw markdown URLs natively
  - Never overwrites — duplicate filenames get a counter suffix
  - Rate limits at 2 seconds between URLs
  - Filenames are clean box names, no source prefix


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 2: quality_check.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Validates raw files against layer-specific quality standards.
  No API key needed — runs entirely offline using pattern matching.
  Run BEFORE the extractor to catch bad data early and save API tokens.

USAGE:
  python scripts/quality_check.py <file_or_directory> [--layer N] [--strict]

ARGUMENTS:
  file_or_directory   Single file or directory of .txt/.md files
  --layer N           Which layer's standards to check against (1-7)
  --strict            Treat warnings as failures

EXAMPLES:
  python scripts/quality_check.py raw/vulnhub/layer1/ --layer 1
  python scripts/quality_check.py raw/htb/layer2/ --layer 2
  python scripts/quality_check.py raw/vulnhub/layer3/ --layer 3 --strict

WHAT IT CHECKS (varies by layer):
  Layer 1: scan output present, service versions, decision reasoning,
           rejects study-guide summaries
  Layer 2: raw tool output present, tool identification
  Layer 3: failure description, recovery/pivot action
  Layer 4: multiple vulnerabilities, prioritization reasoning
  Layer 5: shell context, privilege escalation content
  Layer 6: vulnerability findings, evidence
  Layer 7: scope/authorization context

OUTPUT:
  ✅ PASS              — meets all standards
  ⚠️  PASS (warnings)   — meets required but missing nice-to-haves
  ❌ FAIL              — does not meet standards, fix or skip


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 3: writeup_extractor.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  The main conversion script. Takes raw files, sends to Claude API for
  structured extraction, presents for human review, converts to training
  JSONL, and saves to the correct processed directory.

  This script replaces the old per-layer converter scripts (layer1_converter,
  layer2_converter, etc). It handles all 7 layers with built-in converters.

USAGE:
  python scripts/writeup_extractor.py <file_or_directory> [--layer N]

ARGUMENTS:
  path        Single file or directory of .txt/.md files
  --layer N   Which layer to extract (1-7, default: 1)

EXAMPLES:
  python scripts/writeup_extractor.py raw/vulnhub/layer1/ --layer 1
  python scripts/writeup_extractor.py raw/htb/layer2/ --layer 2
  python scripts/writeup_extractor.py raw/vulnhub/layer3/dc6.txt --layer 3

REVIEW OPTIONS:
  [a] approve  — generates training examples, saves to processed/
  [e] edit     — saves raw JSON for manual editing
  [s] skip     — discards, moves to next file

OUTPUT:
  processed/layer1_recon/{boxname}.jsonl     (Layer 1)
  processed/layer2_parsing/{boxname}.jsonl   (Layer 2)
  processed/layer3_failures/{boxname}.jsonl  (Layer 3)
  processed/layer4_exploits/{boxname}.jsonl  (Layer 4)
  processed/layer5_postexploit/{boxname}.jsonl (Layer 5)
  processed/layer6_reporting/{boxname}.jsonl (Layer 6)
  processed/layer7_ethics/{boxname}.jsonl    (Layer 7)

  Metadata tracked in metadata/{layer_name}_tracker.jsonl

NOTES:
  - Uses claude-sonnet-4-20250514 for extraction
  - Each file generates 1-3 training examples depending on content
  - Always review before approving — Claude can misinterpret
  - Layer-specific review screen shows relevant info per layer


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 4: local_fetcher.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Same as writeup_fetcher.py but for local files (IppSec transcripts,
  manually copied notes, offline writeups). Adds header, runs AI extraction,
  saves to raw/{platform}/layer{N}/.

  Use this when you already have the content as a file and don't need to
  download from a URL.

USAGE:
  python scripts/local_fetcher.py <file_or_dir> --layer N --platform PLATFORM

ARGUMENTS:
  file_or_dir   Single file or directory of .txt/.md files
  --layer N     Which layer (1-7, default: 1)
  --platform    htb / vulnhub / thm / other (default: htb)
  --no-ai       Save without AI extraction

EXAMPLES:
  # Process IppSec transcripts for Layer 1
  python scripts/local_fetcher.py ~/ippsec_transcripts/ --layer 1 --platform htb

  # Process a single transcript for Layer 3
  python scripts/local_fetcher.py transcript_lame.txt --layer 3 --platform htb

  # Process VulnHub notes without AI
  python scripts/local_fetcher.py ~/notes/ --layer 1 --platform vulnhub --no-ai

OUTPUT:
  raw/{platform}/layer{N}/{boxname}.txt

NOTES:
  - Extracts box name from filename automatically
  - Strips date prefixes and common prefixes (transcript_, ippsec_, writeup_)


═══════════════════════════════════════════════════════════════════════════════
SCRIPT 5: exploitdb_fetcher.py
═══════════════════════════════════════════════════════════════════════════════

PURPOSE:
  Searches ExploitDB (via searchsploit) for specific services/versions
  and formats results for Layer 4 (exploit ranking) or Layer 6 (reporting).
  Requires searchsploit to be installed on the system.

  Use AFTER finishing Layers 2-5 from writeups — ExploitDB fills gaps
  in exploit knowledge, it's not a primary source.

USAGE:
  python scripts/exploitdb_fetcher.py <services_file> [--layer N] [--no-ai]

ARGUMENTS:
  services_file   Text file with one service/version per line
  --layer N       4 (exploit ranking) or 6 (reporting only)
  --no-ai         Save raw searchsploit output without formatting

SERVICES FILE FORMAT:
  # ~/clawstrike-data/links/services.txt
  vsftpd 2.3.4
  samba 3.0.20
  apache 2.4.18
  wordpress 5.0
  openssh 4.7p1
  drupal 7
  tomcat 7.0

EXAMPLES:
  python scripts/exploitdb_fetcher.py links/services.txt --layer 4
  python scripts/exploitdb_fetcher.py links/services.txt --layer 6

OUTPUT:
  raw/exploitdb/layer4/{service_name}.txt
  raw/exploitdb/layer6/{service_name}.txt

NOTES:
  - Requires searchsploit installed (sudo apt install exploitdb)
  - Only supports --layer 4 and --layer 6
  - Build the services list from services found in your writeups
  - After fetching, run quality_check and extractor as usual


═══════════════════════════════════════════════════════════════════════════════
DIRECTORY STRUCTURE
═══════════════════════════════════════════════════════════════════════════════

~/clawstrike-data/
├── raw/                              ← Fetcher output (Stage 1)
│   ├── htb/
│   │   ├── layer1/                   ← recon writeups
│   │   ├── layer2/                   ← tool output writeups
│   │   ├── layer3/                   ← failure writeups
│   │   ├── layer4/                   ← exploit ranking writeups
│   │   ├── layer5/                   ← post-exploit writeups
│   │   ├── layer6/                   ← reporting writeups
│   │   └── layer7/                   ← ethics writeups
│   ├── vulnhub/
│   │   ├── layer1/ through layer7/   ← same structure
│   ├── thm/
│   │   ├── layer1/ through layer7/
│   ├── exploitdb/
│   │   ├── layer4/                   ← exploit ranking data
│   │   └── layer6/                   ← reporting data
│   └── other/
│       └── layer1/ through layer7/
│
├── processed/                        ← Extractor output (Stage 3)
│   ├── layer1_recon/                 ← training JSONL
│   ├── layer2_parsing/
│   ├── layer3_failures/
│   ├── layer4_exploits/
│   ├── layer5_postexploit/
│   ├── layer6_reporting/
│   └── layer7_ethics/
│
├── training/                         ← Final merged dataset
│   └── clawstrike_v1.jsonl           ← (created by merge script later)
│
├── eval/                             ← 10% holdout for validation
│   └── clawstrike_eval_v1.jsonl
│
├── links/                            ← URL and service lists
│   ├── vulnhub_links.txt
│   ├── htb_links.txt
│   └── services.txt                  ← for exploitdb_fetcher
│
├── scripts/                          ← This folder
│   ├── README.txt                    ← You are here
│   ├── writeup_fetcher.py            ← Fetch from URLs
│   ├── quality_check.py              ← Validate raw files
│   ├── writeup_extractor.py          ← Extract + convert + save JSONL
│   ├── local_fetcher.py              ← Fetch from local files
│   └── exploitdb_fetcher.py          ← Fetch from ExploitDB
│
└── metadata/                         ← Tracking logs
    ├── fetch_tracker.jsonl
    ├── exploitdb_tracker.jsonl
    ├── layer1_recon_tracker.jsonl
    ├── layer2_parsing_tracker.jsonl
    └── ...


═══════════════════════════════════════════════════════════════════════════════
DEPRECATED SCRIPTS (DO NOT USE)
═══════════════════════════════════════════════════════════════════════════════

The following scripts have been replaced by writeup_extractor.py v2
which handles all 7 layers with built-in converters:

  ✗ layer1_converter.py    → replaced by: writeup_extractor.py --layer 1
  ✗ layer2_converter.py    → replaced by: writeup_extractor.py --layer 2

Delete them if they still exist:
  rm scripts/layer1_converter.py scripts/layer2_converter.py


═══════════════════════════════════════════════════════════════════════════════
QUICK REFERENCE — COMPLETE WORKFLOW
═══════════════════════════════════════════════════════════════════════════════

For URL-based writeups (HTB, VulnHub, THM, blogs):

  python scripts/writeup_fetcher.py links/FILE.txt --layer N
  python scripts/quality_check.py raw/PLATFORM/layerN/ --layer N
  python scripts/writeup_extractor.py raw/PLATFORM/layerN/ --layer N

For local files (IppSec transcripts, notes):

  python scripts/local_fetcher.py PATH --layer N --platform PLATFORM
  python scripts/quality_check.py raw/PLATFORM/layerN/ --layer N
  python scripts/writeup_extractor.py raw/PLATFORM/layerN/ --layer N

For ExploitDB (Layer 4 and 6 only):

  python scripts/exploitdb_fetcher.py links/services.txt --layer 4
  python scripts/quality_check.py raw/exploitdb/layer4/ --layer 4
  python scripts/writeup_extractor.py raw/exploitdb/layer4/ --layer 4


═══════════════════════════════════════════════════════════════════════════════
DELEGATION WORKFLOW (FOR JUNIORS)
═══════════════════════════════════════════════════════════════════════════════

Step 1: Get a links file and layer number from your lead

Step 2: Activate the environment
        source ~/clawstrike-env/bin/activate

Step 3: Run the fetcher
        cd ~/clawstrike-data
        python scripts/writeup_fetcher.py links/FILENAME.txt --layer N

Step 4: Run the quality checker
        python scripts/quality_check.py raw/PLATFORM/layerN/ --layer N

Step 5: Hand over PASSED files to your lead for extraction

DO NOT:
  - Run writeup_extractor.py (lead's job — quality gate)
  - Modify files in processed/ or training/
  - Change the --layer flag without checking with your lead


═══════════════════════════════════════════════════════════════════════════════
QUALITY CHECKLIST (FOR LEADS)
═══════════════════════════════════════════════════════════════════════════════

Before approving any extraction:

  □ Does it contain real data (not summarized)?
  □ Does the reasoning explain WHY, not just WHAT?
  □ Are service versions included where relevant?
  □ Is there actionable content (not just descriptions)?
  □ Are any CVEs mentioned actually real and correct?
  □ Is this different enough from existing examples?
  □ Would a pentester learn something from reading this?

If any answer is NO → edit or skip.


═══════════════════════════════════════════════════════════════════════════════
SCRIPTS TO BE BUILT (FUTURE)
═══════════════════════════════════════════════════════════════════════════════

  merge_training.py       ← Combines all layers into final training JSONL
  eval_splitter.py        ← Holds out 10% for evaluation set


═══════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

"No module named 'anthropic'"
  → pip install anthropic

"No module named 'requests'" or "No module named 'bs4'"
  → pip install requests beautifulsoup4

"ANTHROPIC_API_KEY not set"
  → echo 'export ANTHROPIC_API_KEY=sk-your-key' >> ~/.bashrc
    source ~/.bashrc

"Could not parse Claude response as JSON"
  → The writeup format may be unusual. Try --no-ai and extract manually.

"No space left on device"
  → mkdir -p ~/pip-tmp && export TMPDIR=~/pip-tmp
    Then retry.

"searchsploit: command not found"
  → sudo apt install exploitdb

"File not found: links/..."
  → Make sure you're running from ~/clawstrike-data/

Script hangs or takes too long:
  → AI extraction takes 10-30 seconds per file
  → Ctrl+C to cancel — progress is saved

═══════════════════════════════════════════════════════════════════════════════
