/**
 * @name Potentially overrunning write with float to string conversion
 * @description Buffer write operations that do not control the length
 *              of data written may overflow when floating point inputs
 *              take extreme values.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision medium
 * @id cpp/overrunning-write-with-float
 * @tags reliability
 *       security
 *       external/cwe/cwe-787
 */

import semmle.code.cpp.security.BufferAccess


from
  BufferAccess ba
where
  1=1
select ba, "Potential CWE-787 out-of-bound write."
