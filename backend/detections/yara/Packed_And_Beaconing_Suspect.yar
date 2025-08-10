rule Packed_And_Beaconing_Suspect {
  meta:
    author = "platform"
    mitre = "T1027,T1071.001"
  strings:
    $b1 = "User-Agent: curl/7" nocase
    $b2 = "X-C2-Profile" nocase
  condition:
    filesize < 20MB and uint16(0) == 0x5A4D and (pe.number_of_sections > 6 or pe.entry_point > 0x1000) and any of ($b*)
}