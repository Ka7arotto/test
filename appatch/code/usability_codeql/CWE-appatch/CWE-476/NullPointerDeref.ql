/**
 * @name Use of Null Pointer
 * @description Referencing the contents of a unique pointer after the underlying object has expired may lead to unexpected behavior.
 * @kind problem
 * @precision high
 * @id cpp/null-pointer-dereference
 * @problem.severity warning
 * @security-severity 8.8
 * @tags reliability
 *       security
 *       external/cwe/cwe-476
 */

import cpp

from PointerDereferenceExpr deref
where
  1=1
select deref,
  "Potential CWE-476 NULL Pointer Dereference."
