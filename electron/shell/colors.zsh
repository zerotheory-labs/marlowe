# Benjamin session styling. Never writes to the user's shell configuration.
if [[ -z ${NO_COLOR+x} ]]; then
  export CLICOLOR=1
  export LSCOLORS=${LSCOLORS:-exfxcxdxbxegedabagacad}
  export LS_COLORS=${LS_COLORS:-'di=34:ln=35:ex=32:pi=33:so=36:bd=33:cd=33:or=31:*.zip=35:*.gz=35:*.tar=35'}

  # Keep existing aliases, functions, and prompt frameworks in charge.
  if (( ! ${+aliases[ls]} && ! ${+functions[ls]} )); then
    if [[ $OSTYPE == darwin* || $OSTYPE == freebsd* ]]; then
      alias ls='ls -G'
    elif [[ $OSTYPE == linux* ]]; then
      alias ls='ls --color=auto'
    fi
  fi
  if [[ $PROMPT != *'%F{'* && $PROMPT != *'%{'* && $PROMPT != *$'\e'* ]] && (( ! ${+functions[p10k]} && ! ${+functions[starship_precmd]} )); then
    # A two-line text prompt with theme-aware ANSI foreground colors.
    # Keep data in parameters so branch names never become shell code.
    setopt prompt_subst
    _benjamin_prompt() {
      local command_status=$?
      local branch='' git_label='' status_color='green' status_label='OK'
      if (( $+commands[git] )); then
        branch=$(GIT_OPTIONAL_LOCKS=0 command git symbolic-ref --quiet --short HEAD 2>/dev/null)
        if [[ -z $branch ]]; then
          branch=$(GIT_OPTIONAL_LOCKS=0 command git rev-parse --short HEAD 2>/dev/null)
          [[ -n $branch ]] && branch="detached $branch"
        fi
      fi
      if [[ -n $branch ]]; then
        # Visualize controls, cap long names, and escape zsh prompt directives.
        git_label=${(V)branch}
        (( ${#git_label} > 32 )) && git_label="${git_label[1,29]}..."
        git_label=${git_label//\%/%%}
        _benjamin_git_segment="  %F{magenta}git $git_label%f"
      else
        _benjamin_git_segment=''
      fi
      if (( command_status != 0 )); then
        status_color='red'
        status_label="EXIT $command_status"
      fi
      _benjamin_status_segment="  %F{$status_color}$status_label%f"
      _benjamin_prompt_arrow="%F{$status_color}❯%f "
      return 0
    }
    typeset -ga precmd_functions
    precmd_functions=(_benjamin_prompt ${precmd_functions:#_benjamin_prompt})
    PROMPT='%F{blue}%40<…<%~%<<%f${_benjamin_git_segment}${_benjamin_status_segment}'$'\n''${_benjamin_prompt_arrow}'
    _benjamin_prompt
  fi
fi

# A real ANSI sample, printed on request rather than injected into every session.
marlowe-colors() {
  local code
  printf '\n  Marlowe · ANSI palette\n\n'
  for code in 31 32 33 34 35 36 37; do
    printf '  \033[%sm ● %s \033[0m' "$code" "$code"
  done
  printf '\n'
  for code in 91 92 93 94 95 96 97; do
    printf '  \033[%sm ● %s \033[0m' "$code" "$code"
  done
  printf '\n\n'
}
benjamin-colors() { marlowe-colors "$@"; }
