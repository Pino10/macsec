# Joern on the Java pair

Joern 4.0.691, macOS arm64, OpenJDK 21 (extracted to /tmp, not installed system-wide).

```
joern-parse corpus/sql/java -o cpg-java.bin
joern cpg-java.bin --script q.sc
```

`q.sc` selects calls named `createQuery` whose argument code contains `" + "`:

```scala
import io.shiftleft.semanticcpg.language._
val hits = cpg.call.name("createQuery").filter(c => c.argument.code.l.exists(_.contains(" + "))).l
```

Result: `Hibernate.java:9` (vulnerable) and not `HibernateClean.java:10` (bound parameter).

- Java holdout pair (one vulnerable, one clean): **precision 1.0, recall 1.0**.
- The other 31 corpus cases are PHP, Python, JavaScript, TypeScript, Go, Ruby and C#, which this
  single Java frontend does not cover. No whole-corpus Joern number is claimed.
- Parse plus query took about two minutes on two small Java files. That is the number that matters
  for the decision: Joern is not fast enough to run on every review without a strong reason.

The acceptance rule is unchanged: Joern ships only if it beats 0.5 holdout recall on the whole
corpus, stays under one false positive in ten clean files, and justifies its runtime and 1.76 GB.
The Java pair is a first data point, not the decision.
