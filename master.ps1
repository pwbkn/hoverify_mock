# Hoverify API Tools Master Script
# This script provides a menu for various Hoverify and other API tools
# Run with: irm https://raw.githubusercontent.com/pwbkn/hoverify_mock/refs/heads/main/master.ps1 | iex

# ASCII Art Banner
function Show-Banner {
    $bannerText = @"
 _____           _     _   _  __ _       _____           _     
|_   _|         | |   | \ | |/ _(_)     |_   _|         | |    
  | | ___   ___ | |__ |  \| | |_ _  ___   | |  ___   ___| |___ 
  | |/ _ \ / _ \| '_ \| . ` |  _| |/ _ \  | | / _ \ / _ \ / __|
  | | (_) | (_) | | | | |\  | | | |  __/  | || (_) | (_) \__ \
  \_/\___/ \___/|_| |_\_| \_|_| |_|\___|  \_/ \___/ \___/|___/
"@
    Write-Host $bannerText -ForegroundColor Cyan
    Write-Host "`nAPI Tools Master Script`n" -ForegroundColor Yellow
}

# Check for administrative privileges
function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as admin, restart script with admin privileges
if (-not (Test-Admin)) {
    Write-Host "This script requires administrative privileges." -ForegroundColor Yellow
    Write-Host "Attempting to restart with admin privileges..." -ForegroundColor Yellow
    
    # Store the current command line arguments to pass to the elevated process
    $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"iex ((New-Object System.Net.WebClient).DownloadString('$($MyInvocation.MyCommand.Source)'))`""
    Start-Process PowerShell -ArgumentList $arguments -Verb RunAs
    exit
}

# Function to run Hoverify Mock Server script
function Start-HoverifyMock {
    Write-Host "Launching Hoverify Mock Server..." -ForegroundColor Yellow
    
    # Here we would normally download and run the script
#     $script = @'
# # Hoverify API Mock Server Setup Script
# # This is a placeholder - the actual script would be downloaded from GitHub

# Write-Host "Setting up Hoverify Mock Server..." -ForegroundColor Green
# # Setup steps would go here

# Write-Host "Hoverify Mock Server setup complete!" -ForegroundColor Green
# '@
    
    # For demonstration purposes only - in real use, we would use:
   Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/pwbkn/hoverify_mock/refs/heads/main/hoverify-mock.ps1')
    
    # Invoke-Expression $script
    
    Read-Host "Press Enter to return to the main menu"
}

# Function to run Other Tech Tool
function Start-OtherTechTool {
    Write-Host "This is a placeholder for another tech tool." -ForegroundColor Yellow
    
    # Here you would implement another tool or download its script
    
    Read-Host "Press Enter to return to the main menu"
}

# Function to run a third Tech Tool (placeholder)
function Start-TechTool3 {
    Write-Host "This is a placeholder for a third tech tool." -ForegroundColor Yellow

    # Placeholder for actual tool implementation
    Write-Host "Tech Tool 3 - Functionality not yet implemented." -ForegroundColor Red

    Read-Host "Press Enter to return to the main menu"
}


# Show menu
function Show-Menu {
    Clear-Host
    Show-Banner
    
    Write-Host "=== TECH TOOLS MENU ===" -ForegroundColor Green
    Write-Host
    Write-Host "1. [" -NoNewline
    Write-Host "HOVERIFY" -ForegroundColor Cyan -NoNewline
    Write-Host "] Hoverify API Mock Server"
    Write-Host "2. [" -NoNewline
    Write-Host "TECH2" -ForegroundColor Magenta -NoNewline
    Write-Host "] Other Tech Tool"
    Write-Host "3. [" -NoNewline
    Write-Host "TECH3" -ForegroundColor Yellow -NoNewline
    Write-Host "] Tech Tool 3 (Placeholder)"  # Added menu item
    Write-Host "X. [" -NoNewline
    Write-Host "EXIT" -ForegroundColor Red -NoNewline
    Write-Host "] Exit"
    Write-Host
    Write-Host -NoNewline "Choose an option: "
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host

    switch ($choice) {
        '1' { Start-HoverifyMock }
        '2' { Start-OtherTechTool }
        '3' { Start-TechTool3 }  # Call the third tool function
        'x' { Write-Host "Exiting..."; break } #correct exit
		'X' { Write-Host "Exiting..."; break } #correct exit
        default { Write-Host "Invalid option. Please try again." -ForegroundColor Red }
    }

} while ($choice -ne 'x' -and $choice -ne 'X')
