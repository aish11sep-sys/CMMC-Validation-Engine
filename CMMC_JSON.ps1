#CMMC - LEVEL 1 (JSON output for Module 2)

Function Check-IdentifyUsers {
    $Users = Get-LocalUser
    $GuestEnabled = ($Users | Where-Object{$_.Name -eq "Guest" -and $_."Enabled"}).Count -gt 0
    $Passed = -not $GuestEnabled
    [PSCustomObject]@{
        practice_no = 5
        far_ref     = "b.1.v"
        domain      = "IA"
        coverage    = "FULL"
        check       = "Identify system users and processes"
        result      = if ($Passed) { "PASS" } else { "FAIL" }
        confidence  = "HIGH"
        evidence    = "Get-LocalUser: Guest.Enabled = $GuestEnabled"
    }
}

Function Check-PasswordRequired {
    $User = Get-LocalUser -Name $env:USERNAME
    $Passed = $User.PasswordRequired
    [PSCustomObject]@{
        practice_no = 6
        far_ref     = "b.1.vi"
        domain      = "IA"
        coverage    = "FULL"
        check       = "Authentication before access"
        result      = if ($Passed) { "PASS" } else { "FAIL" }
        confidence  = "HIGH"
        evidence    = "Get-LocalUser: PasswordRequired = $Passed"
    }
}

Function Check-Firewall {
    $Profiles = Get-NetFirewallProfile
    $AllEnabled = ($Profiles | Where-Object {-not $_.Enabled}).Count -eq 0
    [PSCustomObject]@{
        practice_no = 10
        far_ref     = "b.1.x"
        domain      = "SC"
        coverage    = "FULL"
        check       = "Boundary protection (firewall)"
        result      = if ($AllEnabled) { "PASS" } else { "FAIL" }
        confidence  = "HIGH"
        evidence    = "Get-NetFirewallProfile: AllProfilesEnabled = $AllEnabled"
    }
}

Function Check-PatchStatus {
    $LatestPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $DaysSincePatch = (Get-Date) - $LatestPatch.InstalledOn
    $Passed = $DaysSincePatch.Days -le 30
    [PSCustomObject]@{
        practice_no = 12
        far_ref     = "b.1.xii"
        domain      = "SI"
        coverage    = "FULL"
        check       = "Identify, report, correct system flaws timely"
        result      = if ($Passed) { "PASS" } else { "FAIL" }
        confidence  = "HIGH"
        evidence    = "Get-HotFix: DaysSinceLastPatch = $($DaysSincePatch.Days)"
    }
}

Function Check-Antivirus {
    $DefenderStatus = Get-MpComputerStatus
    $DefenderActive = $DefenderStatus.RealTimeProtectionEnabled

    $OtherAV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Where-Object { $_.displayName -ne "Windows Defender" }
    $OtherAVPresent = ($OtherAV).Count -gt 0

    $Passed = $DefenderActive -or $OtherAVPresent

    $Confidence = if ($DefenderActive) { "HIGH" }
                  elseif ($OtherAVPresent) { "MEDIUM" }
                  else { "HIGH" }

    [PSCustomObject]@{
        practice_no = 15
        far_ref     = "b.1.xv"
        domain      = "SI"
        coverage    = "FULL"
        check       = "Real-time malicious code scanning"
        result      = if ($Passed) { "PASS" } else { "FAIL" }
        confidence  = $Confidence
        evidence    = "DefenderActive=$DefenderActive, OtherAVPresent=$OtherAVPresent"
    }
}

# Collect all 5 results
$Results = @(
    Check-IdentifyUsers
    Check-PasswordRequired
    Check-Firewall
    Check-PatchStatus
    Check-Antivirus
)

# Wrap in the top-level object Zafar's schema expects
$Output = [PSCustomObject]@{
    schema_version = "1.0"
    generated_utc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    host           = $env:COMPUTERNAME
    asset_id       = "PLACEHOLDER-ASSET-ID"
    results        = $Results
}

# Convert to JSON and display it
$Output | ConvertTo-Json -Depth 5
