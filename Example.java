rules:
- id: my_pattern_id
  pattern: |
      public $RETURN $METHOD(...){
        ...
        make_transaction($T);
        ...
      }
  message: Semgrep found a match
  languages: [java]
  severity: Error

rules:
- id: jwt-verify-false
  message: JWT library set to verify=false. This is an Auth bypass vulnerabltity
  languages: [python]
  patterns: 
- pattern-inside: |
         def $FUN(...):
          ...
  pattern-either:
- pattern: jwt.decode(..., verify=false, ...) 
  languages: [python]
  severity: Error
