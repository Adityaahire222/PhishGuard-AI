# Evaluation datasets

Place evaluation datasets in this directory only when their licenses and privacy terms allow it.
Prefer synthetic or appropriately anonymized messages. Record each dataset's source, license,
version, preprocessing steps, and label definitions before using it for evaluation. Do not commit
API keys, private messages, or other sensitive data.

## CSV format

The evaluation script expects a UTF-8 CSV with a header and these columns:

```csv
email_text,label
"Your mailbox is full; verify your password immediately.",PHISHING
"The team meeting has moved to 2 PM.",LEGITIMATE
```

`email_text` must be non-empty and no more than 20,000 characters. `label` is case-insensitive
and must be `PHISHING`, `LEGITIMATE`, `SUSPICIOUS`, or `INCONCLUSIVE`. Missing text, missing or
unknown labels, and empty datasets are rejected. Exact duplicate message bodies are counted and
reported but retained, so decide before evaluation whether repeated samples are meaningful.

The script sends each message to the running local `/detect` endpoint. It does not follow or open
URLs in message text and does not write message bodies to reports or logs. Keep raw datasets
private and outside version control where required by their license or privacy terms.

## Preparing `.eml` sources

Use `scripts/preprocess_emails.py` to extract subjects and readable message bodies into this CSV
format. It prefers `text/plain` and falls back to visible text from `text/html`; attachments are
ignored, and links are not opened or fetched. Labels must be supplied in the manifest.

The backward-compatible directory-level format applies one explicit label to every `.eml` below
each directory:

```json
{
  "sources": [
    {"path": "raw/phishing", "label": "PHISHING"},
    {"path": "raw/legitimate", "label": "LEGITIMATE"}
  ]
}
```

To preserve different labels for individual emails, use the optional `files` list. Each `path`
must be a relative path to one existing `.eml` file, resolved from the manifest's directory. It
may be used by itself or alongside `sources`:

```json
{
  "files": [
    {"path": "raw/reviewed/message-000002.eml", "label": "PHISHING"},
    {"path": "raw/reviewed/message-000003.eml", "label": "INCONCLUSIVE"}
  ]
}
```

Both formats accept only `PHISHING`, `LEGITIMATE`, `SUSPICIOUS`, or `INCONCLUSIVE` labels
(case-insensitive). If the same file is included by multiple sources or file entries with different
labels, preprocessing stops with an error. Assign labels only from documented source annotations
or manual review; the script does not infer them from message content.

The script excludes empty messages and messages over 20,000 extracted characters, then removes
exact duplicate extracted texts across all selected files. It prints counts for exclusions and
output rows. Each processed CSV row also has a `source_files` column containing a JSON array of
relative `.eml` paths. If identical extracted text occurs in multiple files with the same label,
it remains one evaluation row and the column lists every contributing source path. If identical
text has conflicting labels, preprocessing stops with an error naming the labels and source paths;
resolve the manifest labels before retrying. It never selects a first, last, or majority label for
conflicting duplicate content, and detects this before writing the output CSV. The evaluator copies
this identifier into `predictions.csv` beside the sample ID. Older processed CSVs without
`source_files` remain supported; their prediction rows use `UNKNOWN` as the source identifier.
Keep raw messages and output private as required by their source terms.

## Raw corpus review inventory

Generate `review_inventory.json` from the raw `.eml` corpus, approved manifest, and existing
human review decisions with:

```powershell
.\.venv\Scripts\python.exe scripts\build_review_inventory.py --datasets-dir datasets --output datasets\review_inventory.json
```

The inventory has one record per source `.eml`, with a path relative to `datasets/`, a
`review_status` (`APPROVED`, `REJECTED`, or `UNREVIEWED`), and an `approved_label` only for
approved records. Approved labels must agree with both the manifest and the human review decision.
Rejected and unreviewed files have a null label; unreviewed files are never labeled from their
content or filenames. Review and manifest references, plus an evidence note, preserve the basis
for each status.

`exact_content_group_id` is a stable SHA-256 identifier computed from the exact extracted text
returned by `scripts.preprocess_emails.extract_email`. This reuses preprocessing's decoding,
plain-text preference, HTML-visible-text fallback, and whitespace handling. Identical extracted
text gets the same ID; an empty extracted message has no ID. A shared ID establishes exact
extracted-text equality only; it does not establish campaign identity. Singleton messages also
have an ID, so a duplicate group is an ID shared by more than one record.

`related_group_id` is populated only for the two relationships recorded in existing review notes:
000004/000005 and 000007/000008. Each is marked `REVIEW_SUPPORTED_NOT_VERIFIED`; this records the
reviewer's reported template relationship, not an independently verified campaign. The inventory
does not infer further related groups or near duplicates. It does not assign development/holdout
splits. Review status is read from `review_decisions_batch_01.json`, and approved labels are
cross-checked against `manifest.json`; inconsistent or missing referenced records stop generation.

The inventory metadata carries forward the corpus attribution and license recorded in the
manifest. Keep those notes with derived data, and treat the raw corpus as potentially identifying.

## Human-review queue

Build a queue from inventory records marked `UNREVIEWED` with:

```powershell
.\.venv\Scripts\python.exe scripts\build_review_queue.py --inventory datasets\review_inventory.json --datasets-dir datasets --json-output datasets\review_queue_unreviewed.json --markdown-output datasets\review_queue_unreviewed.md
```

The JSON file is the machine-readable queue; the Markdown file is a review worksheet. Each item
has a stable sample ID derived from its exact-content group, the full list of source paths in that
group, and a separate list of the unreviewed source files represented by the item. Exact duplicate
groups are queued once, with header information for each unreviewed source. If a group also has an
already reviewed source, its path is retained for provenance, but its label is not copied into the
queue.

The default extracted body limit is 4,000 characters per queue item. `body_truncated` indicates
when additional text was omitted. Subject, sender, reply-to, and saved authentication/routing
headers are included when available. Missing headers are shown as absent and are not treated as
evidence of phishing or legitimate delivery. The script uses the same text-only extraction as
preprocessing; it does not open links, fetch remote content, save or inspect attachments, or execute
email content. The Markdown renderer HTML-escapes untrusted values and places them in fenced code
blocks whose fences cannot be closed by the message text. Reviewers should still treat all message
content and headers as untrusted input.

Every item starts with blank proposed-label, evidence, reviewer-decision, and rationale fields.
The generator does not assign labels or use model predictions. Queue grouping uses only the exact
duplicate groups already computed by the inventory, so it cannot detect near duplicates or infer
new campaign relationships. This workflow creates no development/holdout split. Keep source
attribution and privacy handling with both queue files.

From the project root, create the manifest and run:

```powershell
python scripts/preprocess_emails.py datasets/manifest.json datasets/real_evaluation.csv
```

Then evaluate that output with the existing evaluator command documented above. Keep the real
evaluation CSV separate from `synthetic_smoke_test.csv`.

## Jose Nazario Phishing Corpus: 2015 collection

The converted messages in `raw/phishing-2015-eml/` came from the Jose Nazario Phishing Corpus,
2015 collection: <https://monkey.org/~jose/phishing/>. The corpus README states that the messages
are hand classified but that classification errors may occur; this is a source-level description,
not a guarantee that every individual message is correct. The source specifies the CC BY 4.0
license, which requires attribution when sharing the material or derivatives. Preserve attribution
to Jose Nazario, link to the corpus and license, and note the mbox-to-`.eml` conversion. The README
also notes that later mailboxes are not anonymized, so handle the messages as potentially
identifying data.

Do not add the whole directory under a single label. `manifest.json` uses individually reviewed
per-file entries for the current approved subset. The preprocessor retains the original `.eml`
paths as provenance in processed data; the manifest metadata records that `message-000003.eml` is
a probable duplicate of `message-000002.eml`.
