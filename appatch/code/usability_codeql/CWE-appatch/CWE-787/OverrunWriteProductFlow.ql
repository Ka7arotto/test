/**
 * @name Overrunning write
 * @description Exceeding the size of a static array during write or access operations
 *              may result in a buffer overflow.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision medium
 * @id cpp/overrun-write
 * @tags reliability
 *       security
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.ir.dataflow.internal.ProductFlow
import semmle.code.cpp.ir.IR
import semmle.code.cpp.models.interfaces.Allocation
import semmle.code.cpp.models.interfaces.ArrayFunction
import semmle.code.cpp.rangeanalysis.new.internal.semantic.analysis.RangeAnalysis
import semmle.code.cpp.rangeanalysis.new.internal.semantic.SemanticExprSpecific
import semmle.code.cpp.rangeanalysis.new.RangeAnalysisUtil
import codeql.util.Unit

VariableAccess getAVariableAccess(Expr e) { e.getAChild*() = result }

/**
 * Holds if `(n, state)` pair represents the source of flow for the size
 * expression associated with `alloc`.
 */
predicate hasSize(HeuristicAllocationExpr alloc, DataFlow::Node n, int state) {
  exists(VariableAccess va, Expr size, int delta |
    size = alloc.getSizeExpr() and
    // Get the unique variable in a size expression like `x` in `malloc(x + 1)`.
    va = unique( | | getAVariableAccess(size)) and
    // Compute `delta` as the constant difference between `x` and `x + 1`.
    bounded(any(Instruction instr | instr.getUnconvertedResultExpression() = size),
      any(LoadInstruction load | load.getUnconvertedResultExpression() = va), delta) and
    n.asExpr() = va and
    state = delta
  )
}

predicate isSinkPairImpl(
  CallInstruction c, DataFlow::Node bufSink, DataFlow::Node sizeSink, int delta, Expr eBuf
) {
  exists(
    int bufIndex, int sizeIndex, Instruction sizeInstr, Instruction bufInstr, ArrayFunction func
  |
    bufInstr = bufSink.asInstruction() and
    c.getArgument(bufIndex) = bufInstr and
    sizeInstr = sizeSink.asInstruction() and
    c.getStaticCallTarget() = func and
    pragma[only_bind_into](func)
        .hasArrayWithVariableSize(pragma[only_bind_into](bufIndex),
          pragma[only_bind_into](sizeIndex)) and
    bounded(c.getArgument(sizeIndex), sizeInstr, delta) and
    eBuf = bufInstr.getUnconvertedResultExpression()
  )
}

from FunctionCall fc
where fc.getTarget().getName().matches("%WARN%") or fc.getTarget().getName().matches("%ALIGN%") or fc.getTarget().getName().matches("%msg_new%") or fc.getTarget().getName().matches("%write%") or fc.getTarget().getName().matches("%Init%") or fc.getTarget().getName().matches("%skb_put%") or fc.getTarget().getName().matches("%addstr%") or fc.getTarget().getName().matches("%copy_from%")
select fc,"Potential CWE-787 out-of-bound write."


