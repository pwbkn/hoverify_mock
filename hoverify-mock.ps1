# Hoverify API Mock Server Setup Script
# Can be run directly with: irm https://raw.githubusercontent.com/username/repo/hoverify-mock.ps1 | iex

# ASCII Art Banner
function Show-Banner {
    $bannerText = @"
 _   _                      _  __       
| | | | _____   _____ _ __(_)/ _|_   _ 
| |_| |/ _ \ \ / / _ \ '__| | |_| | | |
|  _  | (_) \ V /  __/ |  | |  _| |_| |
|_| |_|\___/ \_/ \___|_|  |_|_|  \__, |
                                 |___/ 
    __  ___         __      _____                     
   /  |/  /__  ____/ /__   / ___/___  ______   _____ 
  / /|_/ / _ \/ __  / _ \  \__ \/ _ \/ ___/ | / / _ \
 / /  / /  __/ /_/ /  __/ ___/ /  __/ /   | |/ /  __/
/_/  /_/\___/\__,_/\___/ /____/\___/_/    |___/\___/ 
"@
    Write-Host $bannerText -ForegroundColor Cyan
    Write-Host "`nHoverify API Mock Server Setup`n" -ForegroundColor Yellow
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

# Check for installed dependencies
function Check-Dependencies {
    $dependencies = @{
        "NodeJS" = { 
            try { 
                $nodeVersion = node -v
                return $true, $nodeVersion 
            } catch { 
                return $false, "Not installed" 
            } 
        }
        "NPM" = { 
            try { 
                $npmVersion = npm -v
                return $true, $npmVersion 
            } catch { 
                return $false, "Not installed" 
            } 
        }
        "OpenSSL" = { 
            try { 
                $opensslVersion = (openssl version) -replace '^OpenSSL\s+'
                return $true, $opensslVersion 
            } catch { 
                return $false, "Not installed" 
            } 
        }
    }
    
    Write-Host "Checking dependencies..." -ForegroundColor Yellow
    $missingDeps = $false
    
    foreach ($dep in $dependencies.Keys) {
        $result, $version = & $dependencies[$dep]
        if ($result) {
            Write-Host "  ✓ $dep" -ForegroundColor Green -NoNewline
            Write-Host " - $version" -ForegroundColor Gray
        } else {
            Write-Host "  ✗ $dep - missing" -ForegroundColor Red
            $missingDeps = $true
        }
    }
    
    if ($missingDeps) {
        Write-Host "`nMissing dependencies detected. Please install them before continuing." -ForegroundColor Red
        Write-Host "  Node.js: https://nodejs.org/" -ForegroundColor Yellow
        Write-Host "  OpenSSL: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
        
        $install = Read-Host "Would you like to try to install them automatically? (y/n)"
        if ($install -eq 'y') {
            try {
                Write-Host "Installing Node.js using winget..." -ForegroundColor Yellow
                Start-Process -FilePath "winget" -ArgumentList "install -e --id OpenJS.NodeJS" -Wait
                
                Write-Host "Installing OpenSSL using winget..." -ForegroundColor Yellow
                Start-Process -FilePath "winget" -ArgumentList "install -e --id ShiningLight.OpenSSL" -Wait
                
                Write-Host "`nPlease restart this script after installation completes." -ForegroundColor Green
                Read-Host "Press Enter to exit"
                exit
            } catch {
                Write-Host "Failed to automatically install dependencies. Please install them manually." -ForegroundColor Red
                Read-Host "Press Enter to exit"
                exit
            }
        } else {
            Write-Host "Please install the missing dependencies and run this script again." -ForegroundColor Yellow
            Read-Host "Press Enter to exit"
            exit
        }
    }
    
    Write-Host "All dependencies are installed." -ForegroundColor Green
}

# Define paths
$baseDir = Join-Path $env:USERPROFILE "HoverifyMock"
$serverDir = Join-Path $baseDir "server"
$certsDir = Join-Path $baseDir "certificates"
$backupDir = Join-Path $baseDir "backups"
$serverJsPath = Join-Path $serverDir "server.js"
$packageJsonPath = Join-Path $serverDir "package.json"

# Create directories
function Create-Directories {
    Write-Host "Creating directories..." -ForegroundColor Yellow
    
    if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir | Out-Null }
    if (-not (Test-Path $serverDir)) { New-Item -ItemType Directory -Path $serverDir | Out-Null }
    if (-not (Test-Path $certsDir)) { New-Item -ItemType Directory -Path $certsDir | Out-Null }
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
    
    Write-Host "Directories created successfully." -ForegroundColor Green
}

# Create server.js file
function Create-ServerFile {
    Write-Host "Creating server.js file..." -ForegroundColor Yellow
    
    $serverCode = @'
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const PORT = 443; // HTTPS default port

// Enable CORS for all routes
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Mock data
const mockToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log('Headers:', req.headers);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', req.body);
  }
  next();
});

// Activation endpoint
app.post('/app/activate', (req, res) => {
  console.log('Activation request received:', req.body);
  res.json({
    status: ":)",
    message: {
      token: mockToken,
      plan: "premium",
      expiry_date: "2099-12-31",
      user: {
        email: req.body.email || "premium@example.com",
        name: "Premium User"
      },
      features: {
        unlimited_usage: true,
        priority_support: true,
        advanced_features: true
      }
    }
  });
});

// Checkup endpoint
app.get('/app/checkup', (req, res) => {
  // Check for authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: ":(",
      error: {
        message: "Unauthorized"
      }
    });
  }

  console.log('Checkup request received with token:', authHeader);
  
  res.json({
    status: ":)",
    message: {
      token: mockToken,
      expired: false,
      renew_message: false,
      plan: "premium",
      expiry_date: "2099-12-31"
    }
  });
});

// Deactivate endpoint
app.post('/app/deactivate', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: ":(",
      error: {
        message: "Unauthorized"
      }
    });
  }

  console.log('Deactivation request received');
  
  res.json({
    status: ":)",
    message: {
      deactivated: true
    }
  });
});

// Get device name endpoint
app.get('/app/device_name', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: ":(",
      error: {
        message: "Unauthorized"
      }
    });
  }

  console.log('Device name request received');
  
  res.json({
    status: ":)",
    message: {
      device_name: "Mocked Device"
    }
  });
});

// Change device name endpoint
app.post('/app/change_device_name', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: ":(",
      error: {
        message: "Unauthorized"
      }
    });
  }

  console.log('Change device name request received:', req.body);
  
  res.json({
    status: ":)",
    message: {
      device_name: req.body.device_name || "New Device Name"
    }
  });
});

// Catch-all route for any other endpoint
app.all('*', (req, res) => {
  console.log('Unknown endpoint requested:', req.url);
  res.json({
    status: ":)",
    message: "Mock server is working"
  });
});

// Create HTTPS server
const fs = require('fs');
const https = require('https');
let httpsServer;

try {
  // Try to use SSL certificates if available
  const privateKey = fs.readFileSync('server.key', 'utf8');
  const certificate = fs.readFileSync('server.crt', 'utf8');
  const credentials = { key: privateKey, cert: certificate };
  
  httpsServer = https.createServer(credentials, app);
  httpsServer.listen(PORT, () => {
    console.log(`HTTPS Mock server running on port ${PORT}`);
  });
} catch (error) {
  // Fall back to HTTP if SSL certs are not available
  console.log('SSL certificates not found, falling back to HTTP');
  app.listen(PORT, () => {
    console.log(`HTTP Mock server running on port ${PORT}`);
  });
}
'@
    
    Set-Content -Path $serverJsPath -Value $serverCode -Force
    
    Write-Host "Server.js file created successfully." -ForegroundColor Green
}

# Create package.json file
function Create-PackageJsonFile {
    Write-Host "Creating package.json file..." -ForegroundColor Yellow
    
    $packageJson = @'
{
  "name": "hoverify-mock-server",
  "version": "1.0.0",
  "description": "Mock server for Hoverify API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5"
  }
}
'@
    
    Set-Content -Path $packageJsonPath -Value $packageJson -Force
    
    Write-Host "Package.json file created successfully." -ForegroundColor Green
}

# Initialize Node.js project
function Initialize-NodeProject {
    Write-Host "Initializing Node.js project..." -ForegroundColor Yellow
    
    # Create package.json file
    Create-PackageJsonFile
    
    # Install dependencies
    Push-Location $serverDir
    Start-Process -FilePath "npm" -ArgumentList "install" -NoNewWindow -Wait
    Pop-Location
    
    Write-Host "Node.js project initialized successfully." -ForegroundColor Green
}

# Generate SSL certificates
function Generate-SSLCertificates {
    Write-Host "Generating SSL certificates..." -ForegroundColor Yellow
    
    # Create OpenSSL configuration file
    $opensslConfigPath = Join-Path $certsDir "openssl.cnf"
    $opensslConfig = @"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = State
L = City
O = Hoverify Mock
OU = Dev
CN = api.tryhoverify.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = api.tryhoverify.com
DNS.2 = localhost
"@
    
    Set-Content -Path $opensslConfigPath -Value $opensslConfig -Force
    
    # Generate private key
    Push-Location $certsDir
    Start-Process -FilePath "openssl" -ArgumentList "genrsa -out server.key 2048" -NoNewWindow -Wait
    
    # Generate self-signed certificate
    Start-Process -FilePath "openssl" -ArgumentList "req -new -x509 -key server.key -out server.crt -days 3650 -config openssl.cnf" -NoNewWindow -Wait
    Pop-Location
    
    # Copy certificates to server directory
    Copy-Item -Path (Join-Path $certsDir "server.key") -Destination $serverDir -Force
    Copy-Item -Path (Join-Path $certsDir "server.crt") -Destination $serverDir -Force
    
    Write-Host "SSL certificates generated successfully." -ForegroundColor Green
}

# Update hosts file
function Update-HostsFile {
    param (
        [switch]$Remove
    )
    
    $hostsFile = "$env:windir\System32\drivers\etc\hosts"
    $domain = "api.tryhoverify.com"
    $entry = "127.0.0.1 $domain"
    
    # Backup hosts file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $backupDir "hosts_$timestamp.backup"
    Copy-Item $hostsFile -Destination $backupFile -Force
    
    if ($Remove) {
        # Remove domain from hosts file
        $content = Get-Content $hostsFile | Where-Object { $_ -notmatch $domain }
        Set-Content -Path $hostsFile -Value $content -Force
        Write-Host "Domain removed from hosts file." -ForegroundColor Green
    } else {
        # Check if domain is already in hosts file
        $hostContent = Get-Content $hostsFile
        if ($hostContent -match $domain) {
            Write-Host "Domain already exists in hosts file." -ForegroundColor Yellow
        } else {
            # Add domain to hosts file
            Add-Content -Path $hostsFile -Value "`r`n$entry" -Force
            Write-Host "Domain added to hosts file." -ForegroundColor Green
        }
    }
    
    # Flush DNS cache
    ipconfig /flushdns
    Write-Host "DNS cache flushed." -ForegroundColor Green
}

# Install SSL certificate
function Install-SSLCertificate {
    Write-Host "Installing SSL certificate..." -ForegroundColor Yellow
    
    $certPath = Join-Path $serverDir "server.crt"
    if (-not (Test-Path $certPath)) {
        Write-Host "Certificate not found. Please generate SSL certificates first." -ForegroundColor Red
        return
    }
    
    # Import certificate to trusted root store
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    
    # Check if certificate is already installed
    $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($existingCert) {
        Write-Host "Certificate is already installed." -ForegroundColor Yellow
    } else {
        $store.Add($cert)
        Write-Host "Certificate installed successfully." -ForegroundColor Green
    }
    
    $store.Close()
}

# Uninstall SSL certificate
function Uninstall-SSLCertificate {
    Write-Host "Uninstalling SSL certificate..." -ForegroundColor Yellow
    
    $certPath = Join-Path $serverDir "server.crt"
    if (-not (Test-Path $certPath)) {
        Write-Host "Certificate not found." -ForegroundColor Red
        return
    }
    
    # Remove certificate from trusted root store
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    
    $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($existingCert) {
        $store.Remove($existingCert)
        Write-Host "Certificate uninstalled successfully." -ForegroundColor Green
    } else {
        Write-Host "Certificate is not installed." -ForegroundColor Yellow
    }
    
    $store.Close()
}

# Start server
function Start-MockServer {
    Write-Host "Starting mock server..." -ForegroundColor Yellow
    
    # Check if server is already running
    $nodeProcesses = Get-Process node -ErrorAction SilentlyContinue
    if ($nodeProcesses) {
        foreach ($process in $nodeProcesses) {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
            if ($cmdLine -match "server.js") {
                Write-Host "Server is already running (PID: $($process.Id))." -ForegroundColor Yellow
                return
            }
        }
    }
    
    # Start server
    Start-Process -FilePath "node" -ArgumentList "$serverJsPath" -WorkingDirectory $serverDir -WindowStyle Normal
    
    Write-Host "Server started successfully!" -ForegroundColor Green
}

# Stop server
function Stop-MockServer {
    Write-Host "Stopping mock server..." -ForegroundColor Yellow
    
    $serverStopped = $false
    
    $nodeProcesses = Get-Process node -ErrorAction SilentlyContinue
    if ($nodeProcesses) {
        foreach ($process in $nodeProcesses) {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
            if ($cmdLine -match "server.js") {
                Stop-Process -Id $process.Id -Force
                Write-Host "Server stopped (PID: $($process.Id))." -ForegroundColor Green
                $serverStopped = $true
            }
        }
    }
    
    if (-not $serverStopped) {
        Write-Host "No server running." -ForegroundColor Yellow
    }
}

# Test server connection
function Test-ServerConnection {
    Write-Host "Testing server connection..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri "https://api.tryhoverify.com/app/activate" -Method Post -ContentType "application/json" -Body '{"email":"test@example.com"}' -SkipCertificateCheck -ErrorAction Stop
        
        Write-Host "Server connection successful!" -ForegroundColor Green
        Write-Host "Response status code: $($response.StatusCode)" -ForegroundColor Green
        Write-Host "Response content: $($response.Content)" -ForegroundColor Gray
    } catch {
        Write-Host "Server connection failed: $_" -ForegroundColor Red
        
        # Check common issues
        $nodeProcesses = Get-Process node -ErrorAction SilentlyContinue
        $serverRunning = $false
        
        if ($nodeProcesses) {
            foreach ($process in $nodeProcesses) {
                $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
                if ($cmdLine -match "server.js") {
                    $serverRunning = $true
                    break
                }
            }
        }
        
        if (-not $serverRunning) {
            Write-Host "The server is not running. Please start the server first." -ForegroundColor Yellow
        }
        
        $hostsFile = "$env:windir\System32\drivers\etc\hosts"
        $domain = "api.tryhoverify.com"
        $hostContent = Get-Content $hostsFile
        
        if ($hostContent -notmatch $domain) {
            Write-Host "The domain is not in your hosts file. Please update the hosts file." -ForegroundColor Yellow
        }
    }
}

# Complete setup
function Setup-Complete {
    Write-Host "Performing complete setup..." -ForegroundColor Yellow
    
    # Create directories
    Create-Directories
    
    # Create server files
    Create-ServerFile
    
    # Initialize Node.js project
    Initialize-NodeProject
    
    # Generate SSL certificates
    Generate-SSLCertificates
    
    # Update hosts file
    Update-HostsFile
    
    # Install SSL certificate
    Install-SSLCertificate
    
    # Start server
    Start-MockServer
    
    Write-Host "`nSetup completed successfully!" -ForegroundColor Green
    Write-Host "The mock server is now running and configured." -ForegroundColor Green
}

# Complete cleanup
function Cleanup-Complete {
    Write-Host "Performing complete cleanup..." -ForegroundColor Yellow
    
    # Stop server
    Stop-MockServer
    
    # Remove domain from hosts file
    Update-HostsFile -Remove
    
    # Uninstall SSL certificate
    Uninstall-SSLCertificate
    
    Write-Host "`nCleanup completed successfully!" -ForegroundColor Green
}

# Show menu
function Show-Menu {
    Clear-Host
    Show-Banner
    
    Write-Host "=== HOVERIFY MOCK SERVER MENU ===" -ForegroundColor Green
    Write-Host
    Write-Host "1. [" -NoNewline
    Write-Host "SETUP" -ForegroundColor Green -NoNewline
    Write-Host "] Complete Setup (all steps)"
    Write-Host "2. [" -NoNewline
    Write-Host "START" -ForegroundColor Green -NoNewline
    Write-Host "] Start Mock Server"
    Write-Host "3. [" -NoNewline
    Write-Host "STOP" -ForegroundColor Red -NoNewline
    Write-Host "] Stop Mock Server"
    Write-Host "4. [" -NoNewline
    Write-Host "TEST" -ForegroundColor Cyan -NoNewline
    Write-Host "] Test Server Connection"
    Write-Host "5. [" -NoNewline
    Write-Host "HOSTS" -ForegroundColor Yellow -NoNewline
    Write-Host "] Update Hosts File"
    Write-Host "6. [" -NoNewline
    Write-Host "REVERT" -ForegroundColor Yellow -NoNewline
    Write-Host "] Revert Hosts File"
    Write-Host "7. [" -NoNewline
    Write-Host "CERT" -ForegroundColor Magenta -NoNewline
    Write-Host "] Install SSL Certificate"
    Write-Host "8. [" -NoNewline
    Write-Host "UNCERT" -ForegroundColor Magenta -NoNewline
    Write-Host "] Uninstall SSL Certificate"
    Write-Host "9. [" -NoNewline
    Write-Host "CLEANUP" -ForegroundColor Red -NoNewline
    Write-Host "] Complete Cleanup (all revert steps)"
    Write-Host "0. [" -NoNewline
    Write-Host "EXIT" -ForegroundColor Gray -NoNewline
    Write-Host "] Exit"
    Write-Host
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" { 
            Check-Dependencies
            Setup-Complete 
            Pause-Execution
        }
        "2" { 
            Start-MockServer 
            Pause-Execution
        }
        "3" { 
            Stop-MockServer 
            Pause-Execution
        }
        "4" { 
            Test-ServerConnection 
            Pause-Execution
        }
        "5" { 
            Update-HostsFile 
            Pause-Execution
        }
        "6" { 
            Update-HostsFile -Remove 
            Pause-Execution
        }
        "7" { 
            Install-SSLCertificate 
            Pause-Execution
        }
        "8" { 
            Uninstall-SSLCertificate 
            Pause-Execution
        }
        "9" { 
            Cleanup-Complete 
            Pause-Execution
        }
        "0" { 
            Exit 
        }
        default { 
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            Pause-Execution
        }
    }
    
    Show-Menu
}

function Pause-Execution {
    Write-Host "`nPress Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host
}

# Main script execution
Check-Dependencies
Show-Menu
