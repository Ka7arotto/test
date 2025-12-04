/**
 * @name Use of unique pointer after lifetime ends
 * @description Referencing the contents of a unique pointer after the underlying object has expired may lead to unexpected behavior.
 * @kind problem
 * @precision high
 * @id cpp/use-of-unique-pointer-after-lifetime-ends
 * @problem.severity warning
 * @security-severity 8.8
 * @tags reliability
 *       security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.models.interfaces.PointerWrapper

predicate isUniquePointerDerefFunction(Function f) {
  exists(PointerWrapper wrapper |
    f = wrapper.getAnUnwrapperFunction() and
    // We only want unique pointers as the memory behind share pointers may still be
    // alive after the shared pointer is destroyed.
    wrapper.(Class).hasQualifiedName(["std", "bsl"], "unique_ptr")
  )
}

from FunctionCall fc
where fc.getTarget().getName().matches("%free%") or fc.getTarget().getName().matches("%unref%") or fc.getTarget().getName().matches("%unlock%") or fc.getTarget().getName().matches("%unregister%") or fc.getTarget().getName().matches("%reset%") or fc.getTarget().getName().matches("%remove%")
select fc,"Potential CWE-416 use-after-free."
