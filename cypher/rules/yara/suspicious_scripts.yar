rule Cypher_SuspiciousScript_Pattern
{
    meta:
        description = "Benign demo pattern for suspicious script installers"
    strings:
        $base64 = "FromBase64String" ascii nocase
        $disable = "Set-MpPreference -DisableRealtimeMonitoring" ascii nocase
    condition:
        any of them
}
