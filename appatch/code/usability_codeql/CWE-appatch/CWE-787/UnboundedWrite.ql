/**
 * @name Unbounded write
 * @description Buffer write operations that do not control the length
 *              of data written may overflow.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision medium
 * @id cpp/unbounded-write
 * @tags reliability
 *       security
 *       external/cwe/cwe-787
 */

import semmle.code.cpp.security.BufferWrite
import semmle.code.cpp.security.FlowSources as FS
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.IRGuards


predicate isUnboundedWrite(BufferWrite bw) {
  not bw.hasExplicitLimit() and // has no explicit size limit
  not exists(bw.getMaxData(_)) // and we can't deduce an upper bound to the amount copied
}

/**
 * Holds if `e` is a source buffer going into an unbounded write `bw` or a
 * qualifier of (a qualifier of ...) such a source.
 */
predicate unboundedWriteSource(Expr e, BufferWrite bw, boolean qualifier) {
  isUnboundedWrite(bw) and e = bw.getASource() and qualifier = false
  or
  exists(FieldAccess fa | unboundedWriteSource(fa, bw, _) and e = fa.getQualifier()) and
  qualifier = true
}

predicate isSource(FS::FlowSource source, string sourceType) { source.getSourceType() = sourceType }

predicate isSink(DataFlow::Node sink, BufferWrite bw, boolean qualifier) {
  unboundedWriteSource(sink.asIndirectExpr(), bw, qualifier)
  or
  // `gets` and `scanf` reads from stdin so there's no real input.
  // The `BufferWrite` library models this as the call itself being
  // the source. In this case we mark the output argument as being
  // the sink so that we report a path where source = sink (because
  // the same output argument is also included in `isSource`).
  bw.getASource() = bw and
  unboundedWriteSource(sink.asDefiningArgument(), bw, qualifier)
}

predicate lessThanOrEqual(IRGuardCondition g, Expr e, boolean branch) {
  exists(Operand left |
    g.comparesLt(left, _, _, true, branch) or
    g.comparesEq(left, _, _, true, branch)
  |
    left.getDef().getUnconvertedResultExpression() = e
  )
}
from
  BufferWrite bw
select bw, "Potential CWE-787 Out-of-bound write"
