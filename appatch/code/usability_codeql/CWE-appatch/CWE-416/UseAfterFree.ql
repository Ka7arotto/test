/**
 * @name Use of pointer after lifetime ends
 * @description Referencing the contents of a unique pointer after the underlying object has expired may lead to unexpected behavior.
 * @kind problem
 * @precision high
 * @id cpp/use-after-free
 * @problem.severity warning
 * @security-severity 8.8
 * @tags reliability
 *       security
 *       external/cwe/cwe-416
 */

import cpp

from PointerDereferenceExpr deref
where
  1=1
select deref,
  "Potential CWE-416 Use-after-free."
