// A starting query for the SQL corpus, to be run with Joern's scripting shell:
//   joern --script scripts/joern-sql.sc --param corpus=corpus/sql
// It is a template, not a validated measurement: print candidate SQL sinks that mix a query with
// request data, then the Python script maps its JSON to the corpus and scores it.
val query = cpg.call
  .filter(_.code.matches("(?s).*(SELECT|INSERT|UPDATE|DELETE).*"))
  .filter(_.code.matches("(?s).*(\\+|%|\\.concat|\\$\\{|format\\().*"))

query.map { c =>
  Map(
    "file" -> c.file.name.headOption.getOrElse(""),
    "line" -> c.lineNumber.getOrElse(-1),
    "code" -> c.code.take(160)
  )
}.toList
