/**
 * @name Likely overrunning warning
 * @description Buffer write operations that do not control the length
 *              of data written may overflow
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision high
 * @id cpp/very-likely-overrunning-warning
 * @tags reliability
 *       security
 *       external/cwe/cwe-125
 */

import cpp

from PointerDereferenceExpr deref
select deref,
  "Potential CWE-125 Out-of-bound read."

