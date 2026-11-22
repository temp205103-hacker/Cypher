rule GuardSnitch_ReverseShell_Pattern
{
    meta:
        description = "Benign demo pattern for reverse-shell one-liners"
    strings:
        $demo1 = "/bin/bash -i >& /dev/tcp/" ascii nocase
        $demo2 = "powershell -nop -c" ascii nocase
    condition:
        any of them
}
