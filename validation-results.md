# Magpie #1924 — IMAP caller-ID validation

AI-generated report prepared with Codex (GPT-6), reviewed with Claude (Opus 5.5).

Summary of retained results from hosted Linux Docker; this page is not a fresh terminal execution.

Source: apache/magpie `ff82fd3544ae52005f3aefea0c29b69948639537`.
Run: https://github.com/leninworld/magpie/actions/runs/41250252481
Environment: Linux x86-64, Python 3.12.13, non-root Docker, 2 CPUs, 10 GiB memory limit.

## Regression and package checks

| Check | Recorded result |
| --- | --- |
| Original package baseline | 31 passed; no failures, errors or skips |
| New regression subset with original production code | 11 expected failures among 30 cases; no errors or skips |
| Full corrected package | 63 passed; no failures, errors or skips |
| All non-manual hooks | Passed, including workspace Ruff, format and mypy |
| Actual affected-member selection and workspace pytest hook | Passed; selector chose tools/mail-source/imap only |
| Separate zizmor audit | Passed in default offline mode (1 ignored, 18 suppressed) |
| Source distribution and wheel | Both built successfully offline |
| Installed wheel API and real console entry point | Passed in a separate environment outside the source directory |

## Corrected behavior checked in the installed package

These are recorded assertions, not reconstructed stdout:

- `read_thread` accepts `report@example.org` and returns the same result as `<report@example.org>`, with a bracketed output ID.
- `create_draft` accepts the bare ID, returns the bracketed ID and keeps `sent` false.
- URL resolution gives the same result for bare and bracketed IDs.
- The real installed `imap-source-thread-url` console command succeeds for both forms and returns `imap://imap.example.org/INBOX;MSGID=report%40example.org`.
- The module was imported from the installed wheel's site-packages, rather than the source checkout.

Mail was synthetic, using the package's existing FakeMailbox fixture. No live IMAP server, real mailbox, native macOS or Windows behavior was tested. Header parsing and the separate missing-root recipient/subject question (#1925) are unchanged.

Final tested patch SHA256: `edbef3f2e5c07b51aba81b1132fed4b312478ad71948f952344a4558487ec9fb`.
All 12 final file hashes were checked. The four test-file formatting changes preserve their Python ASTs.
The owned validation container exited successfully, was verified stopped and was not OOM-killed.
