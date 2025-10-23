_scalws_completion() {
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    if [ "$cword" -eq 1 ]; then
        COMPREPLY=($(compgen -W "network vpc" -- "$cur"))
        return 0
    fi

    case "${words[1]}" in
        network)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=($(compgen -W "add" -- "$cur"))
            fi
            ;;
        vpc)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=($(compgen -W "add delete" -- "$cur"))
            fi
            ;;
    esac
}

complete -F _scalws_completion scalws