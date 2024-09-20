rule FrostyGoop {
meta:
    description = "rule to detect FrostyGoop"
    author = "ShadowStackRe.com"
    date = "2024-09-20"
    Rule_Version = "v1"
    malware_type = "ICS"
    malware_family = "FrostyGoop"
    License = "MIT License, https://opensource.org/license/mit/"
strings:
        $cfgIP = "ip"
        $cfgInputTask = "input-task=[FILE.json]"
        $cfgInputList = "input-list=[FILE.json]"
        $cfgInputTarget = "input-target=[FILE.json]"
        $cfgCycle = "cycle info=[FILE.json]"
        $cfgOutput = "output=[FILE.json]"
        $cfgMode = "read-all,\nread address=[Address int]"
        $strSkip = "Skip"
condition:
        uint16(0) == 0x5a4d and all of them
}
