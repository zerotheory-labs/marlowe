# Session-only command metadata. No subprocesses, history reads, or network I/O.
# A per-session token prevents accidental output from being parsed as metadata;
# it is not a security boundary against code running in this shell.
if [[ -o interactive && -n $BENJAMIN_INTEGRATION_TOKEN ]]; then
  typeset -g _benjamin_integration_token=$BENJAMIN_INTEGRATION_TOKEN
  unset BENJAMIN_INTEGRATION_TOKEN
  _benjamin_hex() {
    local LC_ALL=C value=$1 result='' byte i
    for (( i=1; i<=${#value}; i++ )); do
      builtin printf -v byte '%02x' "'$value[i]"
      result+=$byte
    done
    REPLY=$result
  }
  _benjamin_preexec() {
    local REPLY cwd_hex command_hex
    _benjamin_hex "${PWD[1,4096]}"; cwd_hex=$REPLY
    _benjamin_hex "${1[1,8192]}"; command_hex=$REPLY
    builtin printf '\033]777;Benjamin;%s;S;%s;%s\007' "$_benjamin_integration_token" "$cwd_hex" "$command_hex"
  }
  _benjamin_precmd() {
    local command_status=$? REPLY
    _benjamin_hex "${PWD[1,4096]}"
    builtin printf '\033]777;Benjamin;%s;P;%s;%s\007' "$_benjamin_integration_token" "$command_status" "$REPLY"
    return 0
  }
  typeset -ga preexec_functions precmd_functions
  preexec_functions=(_benjamin_preexec ${preexec_functions:#_benjamin_preexec})
  precmd_functions=(_benjamin_precmd ${precmd_functions:#_benjamin_precmd})
fi
