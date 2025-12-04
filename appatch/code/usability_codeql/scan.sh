rm -r db
codeql database create db --language=c-cpp --command="make"
codeql database analyze db ../codeql/cpp/ql/src/Security/CWE-appatch/ --format=sarif-latest --output=output.sarif
