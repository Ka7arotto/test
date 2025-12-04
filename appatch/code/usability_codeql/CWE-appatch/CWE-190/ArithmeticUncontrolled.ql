/**
 * @name Uncontrolled data in arithmetic expression
 * @description Arithmetic operations on uncontrolled data that is not
 *              validated can cause overflows.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.6
 * @precision high
 * @id cpp/uncontrolled-arithmetic
 * @tags security
 *       external/cwe/cwe-190
 */

import cpp
import semmle.code.cpp.security.Overflow
import semmle.code.cpp.security.Security
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking

/**
 * A function that outputs random data such as `std::rand`.
 */
abstract class RandomFunction extends Function {
  /**
   * Gets the `FunctionOutput` that describes how this function returns the random data.
   */
  FunctionOutput getFunctionOutput() { result.isReturnValue() }
}

/**
 * The standard function `std::rand`.
 */
private class StdRand extends RandomFunction {
  StdRand() {
    this.hasGlobalOrStdOrBslName("rand") and
    this.getNumberOfParameters() = 0
  }
}

/**
 * The Unix function `rand_r`.
 */
private class RandR extends RandomFunction {
  RandR() {
    this.hasGlobalName("rand_r") and
    this.getNumberOfParameters() = 1
  }
}

/**
 * The Unix function `random`.
 */
private class Random extends RandomFunction {
  Random() {
    this.hasGlobalName("random") and
    this.getNumberOfParameters() = 1
  }
}

/**
 * The Windows `rand_s` function.
 */
private class RandS extends RandomFunction {
  RandS() {
    this.hasGlobalName("rand_s") and
    this.getNumberOfParameters() = 1
  }

  override FunctionOutput getFunctionOutput() { result.isParameterDeref(0) }
}

predicate missingGuard(VariableAccess va, string effect) {
  exists(Operation op | op.getAnOperand() = va |
    // underflow - random numbers are usually non-negative, so underflow is
    // only likely if the type is unsigned. Multiplication is also unlikely to
    // cause underflow of a non-negative number.
    missingGuardAgainstUnderflow(op, va) and
    effect = "underflow" and
    op.getUnspecifiedType().(IntegralType).isUnsigned() and
    not op instanceof MulExpr
    or
    // overflow - only report signed integer overflow since unsigned overflow
    // is well-defined.
    op.getUnspecifiedType().(IntegralType).isSigned() and
    missingGuardAgainstOverflow(op, va) and
    effect = "overflow"
  )
}


from FunctionCall fc
where fc.getTarget().getName().matches("%INC%") or fc.getTarget().getName().matches("%div64%")
select fc,"Potential CWE-190 integer overflow."
