/**
 * @name Call to memory access function may overflow buffer
 * @description Incorrect use of a function that accesses a memory
 *              buffer may read or write data past the end of that
 *              buffer.
 * @kind problem
 * @id cpp/overflow-buffer
 * @problem.severity recommendation
 * @security-severity 9.3
 * @tags security
 *       external/cwe/cwe-125
 */

import semmle.code.cpp.security.BufferWrite
import semmle.code.cpp.security.BufferAccess

bindingset[num, singular, plural]
string plural(int num, string singular, string plural) {
  if num = 1 then result = num + singular else result = num + plural
}

from
  ArrayExpr ae
select ae, "Potential CWE-125 Out-of-bound read"
