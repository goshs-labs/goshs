# goshs bash completion

_goshs() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    (( COMP_CWORD > 0 )) && prev="${COMP_WORDS[COMP_CWORD-1]}"

    local flags="--completion \
-i --ip -p --port -d --dir -w --webdav -wp --webdav-port \
-ro --read-only -uo --upload-only -uf --upload-folder -mu --max-upload \
-nc --no-chat -pc --persist-chat -pci --persist-chat-images \
-nd --no-delete -si --silent -I --invisible --ttl --tui \
--template --tpl-var \
-c --cli --catcher -rc -e --embedded -o --output -t --tunnel \
-s --ssl -ss --self-signed -sk --server-key -sc --server-cert \
-p12 --pkcs12 -p12np --p12-no-pass -sl --lets-encrypt \
-sld --le-domains -sle --le-email -slh --le-http -slt --le-tls \
-ftp --ftp-port --ftp-sftp -fkf --ftp-keyfile -fhk --ftp-host-keyfile \
-tftp --tftp-server --tftp-port \
-smb -smb-port -smb-domain -smb-share -smb-wordlist \
-ldap -ldap-port -ldap-jndi -ldap-jndi-base -ldap-wordlist \
-b --basic-auth -ca --cert-auth -H --hash \
-ipw --ip-whitelist -tpw --trusted-proxy-whitelist \
-dns -dns-port -dns-ip -smtp -smtp-port -smtp-domain \
-W --webhook -Wu --webhook-url -We --webhook-events -Wp --webhook-provider \
-C --config -P --print-config -u --user --update -m --mdns -V --verbose -v"

    # --completion flag: offer shell names as values
    if [[ $prev == "--completion" ]]; then
        COMPREPLY=( $(compgen -W "bash fish zsh" -- "$cur") )
        return 0
    fi

    # File-completing flags
    case "$prev" in
        -d|--dir|-uf|--upload-folder|-o|--output|-C|--config|\
        -sk|--server-key|-sc|--server-cert|-p12|--pkcs12|\
        -ca|--cert-auth|-fkf|--ftp-keyfile|-fhk|--ftp-host-keyfile|\
        -smb-wordlist|-ldap-wordlist)
            _filedir
            return 0
            ;;
    esac

    [[ $cur == -* ]] && COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
    return 0
}

complete -o bashdefault -o default -F _goshs goshs
