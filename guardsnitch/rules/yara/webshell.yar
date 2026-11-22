rule GuardSnitch_WebShell_Pattern
{
    meta:
        description = "Benign demo pattern for shell-execution web requests"
    strings:
        $php = "assert($_POST" ascii nocase
        $jsp = "Runtime.getRuntime().exec" ascii nocase
    condition:
        any of them
}
