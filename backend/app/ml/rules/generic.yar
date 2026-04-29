/*
   Generic ransomware indicators — RansomGuard v2
   These rules are intentionally broad. Each match contributes a moderate
   YARA score (0.5 base + 0.15 per match, capped at 1.0).
*/

rule Ransom_Note_Generic
{
    meta:
        author = "RansomGuard"
        description = "Common ransomware ransom-note phrases"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "send bitcoin to" nocase
        $c = "decryption key" nocase
        $d = "all your data" nocase
        $e = "readme_decrypt" nocase
        $f = "how to recover" nocase
    condition:
        2 of them
}

rule Ransom_VSSAdmin_Delete
{
    meta:
        description = "Shadow-copy deletion via vssadmin"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "wbadmin delete catalog" nocase
        $d = "bcdedit /set {default} recoveryenabled No" nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "PowerShell encoded / FromBase64String execution"
    strings:
        $a = "FromBase64String" nocase
        $b = "-EncodedCommand" nocase
        $c = "IEX (" nocase
        $d = "Invoke-Expression" nocase
    condition:
        2 of them
}

rule Crypto_API_Imports
{
    meta:
        description = "Symbol references to crypto APIs typical of file encryption"
    strings:
        $a = "CryptEncrypt"
        $b = "CryptGenKey"
        $c = "BCryptEncrypt"
        $d = "AES_encrypt"
        $e = "RSA_public_encrypt"
    condition:
        2 of them
}

rule Suspicious_Onion_Or_BTC
{
    meta:
        description = "Embedded TOR onion URL or Bitcoin wallet"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/ nocase
        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $btc2 = /bc1[ac-hj-np-z02-9]{6,87}/
    condition:
        any of them
}
