_scalws_completion() {
    local cur prev words cword
    _init_completion -n : || return

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="instances network disk vpc eip secg start stop terminate"
    local instances_subcommands="list disks"
    local network_subcommands="list interface"
    local disk_subcommands="list attach create delete new"
    local vpc_subcommands="list"
    local eip_subcommands="list attach detach"
    local general_opts="-r --region -v --verbose -d --debug -o --owner -z --availability-zone -h --help"

    if [[ ${COMP_CWORD} -eq 1 ]] ; then
        COMPREPLY=( $(compgen -W "${commands} ${general_opts}" -- ${cur}) )
        return 0
    fi

    local command="${COMP_WORDS[1]}"
    case "${command}" in
        instances)
            if [[ ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${instances_subcommands}" -- ${cur}) )
            fi
            ;;
        network)
            if [[ ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${network_subcommands}" -- ${cur}) )
            fi
            ;;
        disk)
            if [[ ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${disk_subcommands}" -- ${cur}) )
            fi
            ;;
        vpc)
            if [[ ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${vpc_subcommands}" -- ${cur}) )
            fi
            ;;
        eip)
            if [[ ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${eip_subcommands}" -- ${cur}) )
            fi
            ;;
        start|stop|terminate|secg)
            # No subcommands for these
            ;;
    esac
}

complete -F _scalws_completion scalws.py