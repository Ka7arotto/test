/**
 * @name Unclear validation of array index
 * @description Accessing an array without first checking
 *              that the index is within the bounds of the array can
 *              cause undefined behavior and can also be a security risk.
 * @kind problem
 * @id cpp/unclear-array-index-validation
 * @problem.severity warning
 * @security-severity 8.8
 * @precision low
 * @tags security
 *       external/cwe/cwe-125
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils
import semmle.code.cpp.security.Security

predicate hasUpperBound(VariableAccess offsetExpr) {
  exists(BasicBlock controlled, StackVariable offsetVar, SsaDefinition def |
    controlled.contains(offsetExpr) and
    linearBoundControls(controlled, def, offsetVar) and
    offsetExpr = def.getAUse(offsetVar)
  )
}

pragma[noinline]
predicate linearBoundControls(BasicBlock controlled, SsaDefinition def, StackVariable offsetVar) {
  exists(GuardCondition guard, boolean branch |
    guard.controls(controlled, branch) and
    cmpWithLinearBound(guard, def.getAUse(offsetVar), Lesser(), branch)
  )
}

predicate readsVariable(LoadInstruction load, Variable var) {
  load.getSourceAddress().(VariableAddressInstruction).getAstVariable() = var
}

predicate hasUpperBoundsCheck(Variable var) {
  exists(RelationalOperation oper, VariableAccess access |
    oper.getAnOperand() = access and
    access.getTarget() = var and
    // Comparing to 0 is not an upper bound check
    not oper.getAnOperand().getValue() = "0"
  )
}

predicate nodeIsBarrierEqualityCandidate(DataFlow::Node node, Operand access, Variable checkedVar) {
  readsVariable(node.asInstruction(), checkedVar) and
  any(IRGuardCondition guard).ensuresEq(access, _, _, node.asInstruction().getBlock(), true)
}

predicate isFlowSource(FlowSource source, string sourceType) { sourceType = source.getSourceType() }

predicate predictableInstruction(Instruction instr) {
  instr instanceof ConstantInstruction
  or
  instr instanceof StringConstantInstruction
  or
  // This could be a conversion on a string literal
  predictableInstruction(instr.(UnaryInstruction).getUnary())
}

from FunctionCall fc
where fc.getTarget().getName().matches("%WARN%") or fc.getTarget().getName().matches("%memdup%")
select fc,"Potential CWE-125 out-of-bound read."
