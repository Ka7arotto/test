/**
 * @name Badly bounded write
 * @description Buffer write operations with a length parameter that
 *              does not match the size of the destination buffer may
 *              overflow.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision high
 * @id cpp/badly-bounded-write
 * @tags reliability
 *       security
 *       external/cwe/cwe-787
 */

import semmle.code.cpp.security.BufferWrite


from BufferWrite bw, int destSize
where
  bw.hasExplicitLimit() and // has an explicit size limit
  destSize = max(getBufferSize(bw.getDest(), _)) and
  bw.getExplicitLimit() > destSize // but it's larger than the destination
select bw,
  "This '" + bw.getBWDesc() + "' operation is limited to " + bw.getExplicitLimit() +
    " bytes but the destination is only " + destSize + " bytes."
