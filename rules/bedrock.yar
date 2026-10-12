rule Bedrock_CheatModule_RTTI : module_features
{
    meta:
        scope = "single_image"
    strings:
        $gui = ".?AVClickGUI@@\x00" nocase
        $combat_killaura = ".?AVKillAura@@\x00" nocase
        $combat_aura = ".?AVAura@@\x00"
        $combat_aimbot = ".?AVAimBot@@\x00" nocase
        $combat_triggerbot = ".?AVTriggerBot@@\x00"
        $support_scaffold = ".?AVScaffold@@\x00"
        $support_nofall = ".?AVNoFall@@\x00"
        $support_antibot = ".?AVAntiBot@@\x00"
        $support_autototem = ".?AVAutoTotem@@\x00"
    condition:
        $gui and any of ($combat_*) and
        3 of ($combat_*, $support_*)
}

rule Bedrock_HorionBorion_ModuleDescriptions : module_features
{
    meta:
        description = "Related combat and building module descriptions"
        scope = "single_image"
    strings:
        $bow = "Aimbot, but for bows"
        $tower = "Like scaffold, but vertically and a lot faster"
        $gui = "The clickgui - toggle everything"
        $combat_killaura = "Killaura\x00"
        $combat_triggerbot = "TriggerBot\x00"
        $combat_chestaura = "ChestAura\x00"
    condition:
        all of ($bow, $tower, $gui) and 2 of ($combat_*)
}

rule Bedrock_Solaris_Features : sample_features
{
    meta:
        description = "Solaris identity together with movement module names"
        scope = "single_image"
    strings:
        $identity = "Solaris | .gg/" wide ascii
        $scaffold = "ScaffoldFly\x00"
        $scaffold_label = "Scaffold Fly\x00" wide ascii
        $noclip = "NoClip\x00"
        $game = "Microsoft.MinecraftUWP_" wide ascii
    condition:
        all of them
}

rule Bedrock_Packet_Loader : loader_features
{
    meta:
        description = "Packet loader hook and remapping messages"
        scope = "single_image"
    strings:
        $client = "\\Packet 3.1" wide ascii
        $game = "Minecraft.Windows.exe" wide ascii
        $client_hook = "[!] Created CI hook"
        $send_hook = "[!] Created send hook"
        $remapped = "[+] Remapped"
        $loaded = "[+] Loaded client"
    condition:
        $client and $game and all of ($client_hook, $send_hook, $remapped, $loaded)
}

rule Bedrock_Kion_ExternalClient : external_client_features
{
    strings:
        $identity = "KionClient" ascii wide nocase
        $packages = "FindPackagesByPackageFamily\x00"
        $read = "ReadProcessMemory\x00"
        $write = "WriteProcessMemory\x00"
        $protect = "VirtualProtectEx\x00"
    condition:
        all of them
}

rule Bedrock_ExternalClient_Profile : review
{
    strings:
        $packages = "FindPackagesByPackageFamily\x00"
        $read = "ReadProcessMemory\x00"
        $write = "WriteProcessMemory\x00"
        $protect = "VirtualProtectEx\x00"
        $allocate = "VirtualAllocEx\x00"
        $modules_first = "Module32First\x00"
        $modules_next = "Module32Next\x00"
        $input_hook = "SetWindowsHookExA\x00"
        $graphics = "D3DXCreateTextureFromFileA\x00"
        $event_log = "ClearEventLogA\x00"
    condition:
        all of them and not Bedrock_Kion_ExternalClient
}
