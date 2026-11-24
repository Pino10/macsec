# SQL corpus: measured engines

Run on 2026-11-24 on macOS arm64. The corpus is 33 cases: 17 vulnerable and 16 clean, with PHP and
Python as the training split and the other six languages as holdout. A finding counts when it is in
the labelled file within two lines of the marked query; several rules at one query count once; a
finding in a clean file is a false positive.

Commands:

- Semgrep: `npm run corpus:sql` (uses `~/MacSec/tools/bin/semgrep`, config `p/sql-injection`).
- Bearer: `bearer scan corpus/sql --format json --output bearer.json`, then filter to SQL rules
  (id or title contains `sql`, or CWE 89) and score. Version 2.1.3.
- Psalm: a temporary composer project with `vimeo/psalm`, a `psalm.xml` pointing at
  `corpus/sql/php`, run `psalm --taint-analysis --output-format=json --no-progress --no-cache`.
  Version 7.17.0. Taint issues only.
- PHPStan: the same project, `phpstan analyse corpus/sql/php --level=max --error-format=json`,
  keeping only messages that name a security concern. Version 2.3.7.
- Joern: not run. There is no Java runtime on this Mac, so it cannot start.

| Engine | Coverage | Precision | Recall | Holdout | What it shows |
| --- | --- | --- | --- | --- | --- |
| Semgrep `p/sql-injection` | all 33 | 1.0 | 0.647 | 0.5 | Misses Laravel raw queries, JS concatenation, Prisma/TypeORM raw calls and Hibernate HQL. |
| Bearer 2.1.3 | all 33 | 0.8 | 0.235 | 0.8 / 0.5 | Finds the Go, Ruby and JavaScript cases; one false positive on a parameterised JS query; misses PHP, Python, TypeScript and Java. |
| Psalm 7.17 taint | PHP (8 cases) | 1.0 | 0.5 | n/a | Catches the PDO insert and raw query; misses both Laravel query-builder cases. |
| PHPStan 2.3.7 | PHP (8 cases) | 0.5 | 0.25 | n/a | Not a security scanner: one flagged query, one false positive on the safe version. |
| Joern | not run | | | | No Java runtime; the query template and parser are ready. |

The engine that is missing the most is not the one with the lowest recall: Bearer has the only false
positive, on a query that uses a bound parameter. That matters more than a miss when the report is
what a person acts on.

These numbers are on 33 samples. They are enough to choose what to measure next, not enough to
declare a winner. The next corpus growth is real application code with no known SQL injection, to
measure false positives on code that was not written for the test.
