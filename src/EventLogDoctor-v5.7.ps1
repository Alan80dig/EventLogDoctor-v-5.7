# EventLogDoctor v5.7 - Windows Diagnostics for AI
# Complete scan of all Windows event logs with hardware analysis
# Version 5.7: Added frequency analysis, ghost devices, BIOS date, confidence markers
# Principles: Read-only, non-invasive, privacy-first

# ================= ЯЗЫКОВЫЕ НАСТРОЙКИ =================
$osLanguage = (Get-WinSystemLocale).Name
$isRussianOS = $osLanguage -like "*ru*" -or $osLanguage -like "*Russian*"

function Write-Localized {
    param([string]$RussianText, [string]$EnglishText)
    if ($isRussianOS) { Write-Host $RussianText } else { Write-Host $EnglishText }
}

function Show-Title {
    if ($isRussianOS) {
        Write-Host "EventLogDoctor v5.7 - Проверка системы" -ForegroundColor Green
        Write-Host "Сбор информации для анализа" -ForegroundColor Yellow
        Write-Host "Запуск через 2 секунды..." -ForegroundColor Gray
    } else {
        Write-Host "EventLogDoctor v5.7 - System Check" -ForegroundColor Green
        Write-Host "Collecting information for analysis" -ForegroundColor Yellow
        Write-Host "Starting in 2 seconds..." -ForegroundColor Gray
    }
}

# ================= ИНИЦИАЛИЗАЦИЯ =================
Clear-Host
Show-Title
Start-Sleep -Seconds 2

# ================= ПРОВЕРКА ПРАВ =================
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    if ($isRussianOS) {
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host "    ОШИБКА: Требуются права администратора!" -ForegroundColor Red
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host ""
        Write-Host "Как запустить правильно:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. Нажмите ПРАВОЙ кнопкой на файле" -ForegroundColor Cyan
        Write-Host "  2. Выберите 'Запуск от имени администратора'" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Или нажмите Enter для автоматического перезапуска" -ForegroundColor Green
        Write-Host "Или любую другую клавишу для выхода" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host "    ERROR: Administrator rights required!" -ForegroundColor Red
        Write-Host "=" * 60 -ForegroundColor Red
        Write-Host ""
        Write-Host "How to run correctly:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. RIGHT-click on the file" -ForegroundColor Cyan
        Write-Host "  2. Select 'Run as administrator'" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Press Enter for automatic restart with admin rights" -ForegroundColor Green
        Write-Host "Or any other key to exit" -ForegroundColor Gray
        Write-Host ""
    }
    
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    if ($key.VirtualKeyCode -eq 13) {
        if ($isRussianOS) {
            Write-Host "`nПерезапуск с правами администратора..." -ForegroundColor Cyan
        } else {
            Write-Host "`nRestarting with administrator rights..." -ForegroundColor Cyan
        }
        Start-Sleep -Seconds 2
        
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        exit
    } else {
        if ($isRussianOS) {
            Write-Host "`nВыход..." -ForegroundColor Gray
        } else {
            Write-Host "`nExiting..." -ForegroundColor Gray
        }
        Start-Sleep -Seconds 1
        exit
    }
}

# ================= НАСТРОЙКИ =================
$OutputFolder = "C:\WindowsDiagnostics"
$ScriptVersion = "5.7"
$DaysToAnalyze = 7

function Write-Step($Step, $Message) {
    Write-Host "[$Step] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error($Message) {
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info($Message) {
    Write-Host "  $Message" -ForegroundColor Gray
}

function Write-Warning($Message) {
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Get-AnonymizedComputerName {
    param([string]$ComputerName)
    
    if ([string]::IsNullOrEmpty($ComputerName)) {
        return "COMP_ANONYMIZED"
    }
    
    if ($ComputerName.Contains('\')) {
        $parts = $ComputerName.Split('\')
        $domain = $parts[0]
        $compName = $parts[1]
        
        if ($domain.Length -gt 3) {
            $maskedDomain = $domain.Substring(0, 3) + ("*" * ($domain.Length - 3))
        } else {
            $maskedDomain = $domain + ("*" * (4 - $domain.Length))
        }
        
        if ($compName.Length -gt 3) {
            $maskedComp = $compName.Substring(0, 3) + ("*" * ($compName.Length - 3))
        } else {
            $maskedComp = $compName + ("*" * (4 - $compName.Length))
        }
        
        return "$maskedDomain\$maskedComp"
    }
    elseif ($ComputerName.Contains('.')) {
        $parts = $ComputerName.Split('.')
        $compName = $parts[0]
        $domain = $parts[1]
        
        if ($compName.Length -gt 3) {
            $maskedComp = $compName.Substring(0, 3) + ("*" * ($compName.Length - 3))
        } else {
            $maskedComp = $compName + ("*" * (4 - $compName.Length))
        }
        
        if ($domain.Length -gt 2) {
            $maskedDomain = $domain.Substring(0, 2) + ("*" * ($domain.Length - 2))
        } else {
            $maskedDomain = $domain + ("*" * (3 - $domain.Length))
        }
        
        return "$maskedComp.$maskedDomain"
    }
    else {
        if ($ComputerName.Length -gt 4) {
            return $ComputerName.Substring(0, 4) + ("*" * ($ComputerName.Length - 4))
        } else {
            return $ComputerName + ("*" * (5 - $ComputerName.Length))
        }
    }
}

$StandardLogs = @{
    System = @("System")
    Application = @("Application")
    Security = @("Security")
    Setup = @("Setup")
    Kernel = @(
        "Microsoft-Windows-Kernel-General/Operational",
        "Microsoft-Windows-Kernel-Power/Operational",
        "Microsoft-Windows-Kernel-Boot/Operational"
    )
    Storage = @(
        "Microsoft-Windows-Storage-Storport/Operational",
        "Microsoft-Windows-StorDiag/Operational"
    )
    NTFS = @("Microsoft-Windows-Ntfs/Operational")
    Network = @(
        "Microsoft-Windows-NetworkProfile/Operational",
        "Microsoft-Windows-NetworkProvisioning/Operational",
        "Microsoft-Windows-NCSI/Operational"
    )
    WMI = @("Microsoft-Windows-WMI-Activity/Operational")
    DHCP = @(
        "Microsoft-Windows-DHCP Client/Operational",
        "Microsoft-Windows-DHCP Server/Operational"
    )
    DNS = @("Microsoft-Windows-DNS Client/Operational")
    PowerShell = @("Windows PowerShell")
    Defender = @(
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Defender/WHC"
    )
    BitLocker = @("Microsoft-Windows-BitLocker-API/Management")
    TaskScheduler = @("Microsoft-Windows-TaskScheduler/Operational")
    WindowsUpdate = @(
        "Microsoft-Windows-WindowsUpdateClient/Operational",
        "Microsoft-Windows-Servicing/Operational"
    )
    AppX = @(
        "Microsoft-Windows-AppXDeploymentServer/Operational",
        "Microsoft-Windows-AppModel-State/Operational"
    )
    UserProfiles = @("Microsoft-Windows-User Profiles Service/Operational")
    GroupPolicy = @("Microsoft-Windows-GroupPolicy/Operational")
    PrintService = @("Microsoft-Windows-PrintService/Operational")
    RemoteDesktop = @("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational")
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# ================= ФУНКЦИИ ДИАГНОСТИКИ =================

function Get-SystemInformation {
    if ($isRussianOS) {
        Write-Step "1/11" "Сбор информации о системе"
    } else {
        Write-Step "1/11" "Collecting system information"
    }
    
    $systemInfo = @{}
    
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $computer = Get-CimInstance Win32_ComputerSystem
        $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS
        
        $originalComputerName = $env:COMPUTERNAME
        $anonymizedComputerName = Get-AnonymizedComputerName -ComputerName $originalComputerName
        
        $totalRAMBytes = $computer.TotalPhysicalMemory
        $totalRAM_GB = [math]::Round($totalRAMBytes / 1GB, 1)
        $availableRAMBytes = $os.FreePhysicalMemory * 1024
        $availableRAM_GB = [math]::Round($availableRAMBytes / 1GB, 2)
        $usedRAM_GB = [math]::Round(($totalRAMBytes - $availableRAMBytes) / 1GB, 2)
        $ramUsagePercent = if ($totalRAMBytes -gt 0) {
            [math]::Round((($totalRAMBytes - $availableRAMBytes) / $totalRAMBytes) * 100, 1)
        } else { 0 }
        
        $hardwareReservedRAM = 0.1
        
        # Получаем дату BIOS
        $biosDate = "N/A"
        try {
            if ($bios.ReleaseDate) {
                $biosDate = $bios.ReleaseDate.ToString("yyyy-MM-dd")
            } elseif ($bios.Version -match "(\d{4})[\.\/](\d{2})[\.\/](\d{2})") {
                $biosDate = "$($matches[1])-$($matches[2])-$($matches[3])"
            }
        } catch {
            $biosDate = "N/A"
        }
        
        $systemInfo = @{
            ComputerName = $anonymizedComputerName
            OriginalComputerName = $originalComputerName
            UserName = "USER_" + (Get-Random -Minimum 1000 -Maximum 9999)
            WindowsName = $os.Caption
            Version = $os.Version
            Build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
            InstallDate = $os.InstallDate.ToString("yyyy-MM-dd")
            LastBoot = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm")
            UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
            TotalRAM_GB = $totalRAM_GB
            AvailableRAM_GB = $availableRAM_GB
            UsedRAM_GB = $usedRAM_GB
            RAMUsagePercent = $ramUsagePercent
            HardwareReservedRAM_GB = $hardwareReservedRAM
            CPU = $processor.Name
            CPU_Cores = $processor.NumberOfCores
            CPU_Threads = $processor.NumberOfLogicalProcessors
            CPU_MaxClock = [math]::Round($processor.MaxClockSpeed / 1000, 1)
            BIOS = $bios.Manufacturer + " " + $bios.SMBIOSBIOSVersion
            BIOS_Date = $biosDate
            Architecture = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
            Timezone = (Get-TimeZone).Id
        }
        
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        $diskInfo = @()
        foreach ($disk in $disks) {
            $freePercent = if ($disk.Size -gt 0) { 
                [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) 
            } else { 0 }
            
            $diskInfo += "$($disk.DeviceID): $([math]::Round($disk.FreeSpace/1GB,1)) GB free of $([math]::Round($disk.Size/1GB,1)) GB ($freePercent%)"
        }
        $systemInfo.Disks = $diskInfo -join " | "
        
        if ($isRussianOS) {
            Write-Info "ОЗУ: $usedRAM_GB ГБ из $totalRAM_GB ГБ ($ramUsagePercent%)"
            Write-Info "Доступно ОЗУ: $availableRAM_GB ГБ"
            Write-Success "Информация о системе собрана"
        } else {
            Write-Info "RAM: $usedRAM_GB GB of $totalRAM_GB GB ($ramUsagePercent%)"
            Write-Info "Available RAM: $availableRAM_GB GB"
            Write-Success "System information collected"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка сбора информации о системе: $_"
        } else {
            Write-Error "Error collecting system information: $_"
        }
    }
    
    return $systemInfo
}

function Check-Temperatures {
    if ($isRussianOS) {
        Write-Step "2/11" "Проверка температур"
    } else {
        Write-Step "2/11" "Checking temperatures"
    }
    
    $temperatures = @{
        CPU = @{}
        GPU = @()
        Disks = @()
        Warnings = @()
    }
    
    try {
        if ($isRussianOS) {
            Write-Info "Сбор информации о температурах..."
        } else {
            Write-Info "Collecting temperature information..."
        }
        
        try {
            $cpuTemps = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
            
            if ($cpuTemps) {
                foreach ($temp in $cpuTemps) {
                    if ($temp.CurrentTemperature -ne $null -and $temp.CurrentTemperature -gt 0) {
                        $tempCelsius = ($temp.CurrentTemperature - 2732) / 10.0
                        
                        $status = if ($tempCelsius -gt 85) { "CRITICAL ⚠️" }
                                elseif ($tempCelsius -gt 75) { "HIGH" }
                                elseif ($tempCelsius -gt 65) { "ELEVATED" }
                                else { "NORMAL" }
                        
                        $temperatures.CPU = @{
                            Temperature = [math]::Round($tempCelsius, 1)
                            Status = $status
                            Unit = "°C"
                        }
                        
                        if ($tempCelsius -gt 75) {
                            if ($isRussianOS) {
                                $temperatures.Warnings += "ВЫСОКАЯ ТЕМПЕРАТУРА CPU: ${tempCelsius}°C"
                            } else {
                                $temperatures.Warnings += "HIGH CPU TEMPERATURE: ${tempCelsius}°C"
                            }
                        }
                        break
                    }
                }
            }
        } catch {}
        
        try {
            $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
            if ($gpus) {
                foreach ($gpu in $gpus) {
                    if ($gpu.AdapterRAM -and $gpu.AdapterRAM -gt 0) {
                        $gpuRAM = [math]::Round($gpu.AdapterRAM / 1GB, 1)
                        $temperatures.GPU += @{
                            Name = $gpu.Name
                            RAM = $gpuRAM
                            Status = "Temperature: N/A (requires admin/OpenHardwareMonitor)"
                        }
                    }
                }
            }
        } catch {}
        
        try {
            $physicalDisks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
            if ($physicalDisks) {
                foreach ($disk in $physicalDisks) {
                    try {
                        $smartData = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_ATAPISmartData -ErrorAction SilentlyContinue | 
                                    Where-Object { $_.InstanceName -like "*$($disk.Index)*" } | 
                                    Select-Object -First 1
                        
                        if ($smartData -and $smartData.Temperature -gt 0) {
                            $tempC = $smartData.Temperature
                            $status = if ($tempC -gt 60) { "HIGH" } else { "NORMAL" }
                            
                            $temperatures.Disks += @{
                                Model = $disk.Model
                                Temperature = $tempC
                                Status = $status
                            }
                            
                            if ($tempC -gt 60) {
                                if ($isRussianOS) {
                                    $temperatures.Warnings += "ВЫСОКАЯ ТЕМПЕРАТУРА ДИСКА: ${tempC}°C"
                                } else {
                                    $temperatures.Warnings += "HIGH DISK TEMPERATURE: ${tempC}°C"
                                }
                            }
                        }
                    } catch { continue }
                }
            }
        } catch {}
        
        if ($temperatures.CPU.Count -eq 0) {
            if ($isRussianOS) {
                $temperatures.CPU = @{ Temperature = "N/A"; Status = "Требуются права администратора" }
            } else {
                $temperatures.CPU = @{ Temperature = "N/A"; Status = "Admin rights required" }
            }
        }
        
        if ($isRussianOS) {
            if ($temperatures.CPU.Temperature -ne "N/A") {
                Write-Info "Температура CPU: $($temperatures.CPU.Temperature)°C [$($temperatures.CPU.Status)]"
            }
            Write-Info "Дисков с температурой: $($temperatures.Disks.Count)"
            Write-Success "Проверка температур завершена"
        } else {
            if ($temperatures.CPU.Temperature -ne "N/A") {
                Write-Info "CPU Temperature: $($temperatures.CPU.Temperature)°C [$($temperatures.CPU.Status)]"
            }
            Write-Info "Disks with temperature: $($temperatures.Disks.Count)"
            Write-Success "Temperature check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Info "  Информация о температурах ограничена"
        } else {
            Write-Info "  Temperature information limited"
        }
    }
    
    return $temperatures
}

function Check-DiskHealth {
    if ($isRussianOS) {
        Write-Step "3/11" "Проверка здоровья дисков"
    } else {
        Write-Step "3/11" "Checking disk health"
    }
    
    $diskHealth = @{
        SMART_Status = @()
        Detailed_SMART = @()
        Temperature = "N/A"
        HealthScore = 100
        Recommendations = @()
        DiskMapping = @()
    }
    
    try {
        if ($isRussianOS) {
            Write-Info "Анализ SMART данных..."
        } else {
            Write-Info "Analyzing SMART data..."
        }
        
        $physicalDisks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
        
        if ($physicalDisks -and $physicalDisks.Count -gt 0) {
            foreach ($disk in $physicalDisks) {
                $healthStatus = "UNKNOWN"
                $icon = "⚪"
                $smartDetails = @()
                
                if ($disk.Status -eq "OK") {
                    $healthStatus = "HEALTHY"
                    $icon = "✅"
                } elseif ($disk.Status -eq "Pred Fail") {
                    $healthStatus = "WARNING - Possible failure"
                    $icon = "⚠️"
                    $diskHealth.HealthScore -= 30
                    if ($isRussianOS) {
                        $diskHealth.Recommendations += "Диск показывает признаки возможного отказа"
                    } else {
                        $diskHealth.Recommendations += "Disk shows signs of possible failure"
                    }
                } elseif ($disk.Status -eq "Error") {
                    $healthStatus = "CRITICAL - Failure detected"
                    $icon = "🔴"
                    $diskHealth.HealthScore -= 50
                    if ($isRussianOS) {
                        $diskHealth.Recommendations += "Диск имеет критические ошибки"
                    } else {
                        $diskHealth.Recommendations += "Disk has critical errors"
                    }
                } else {
                    $healthStatus = $disk.Status
                }
                
                try {
                    $predictStatus = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.InstanceName -like "*$($disk.Index)*" } | 
                                   Select-Object -First 1
                    
                    if ($predictStatus) {
                        $smartDetails += "PredictFailure: $($predictStatus.PredictFailure)"
                    }
                } catch {}
                
                try {
                    $smartData = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_ATAPISmartData -ErrorAction SilentlyContinue | 
                                Where-Object { $_.InstanceName -like "*$($disk.Index)*" } | 
                                Select-Object -First 1
                    
                    if ($smartData -and $smartData.Temperature -gt 0) {
                        $tempC = $smartData.Temperature
                        if ($diskHealth.Temperature -eq "N/A") {
                            $diskHealth.Temperature = "$tempC°C"
                        }
                        
                        if ($tempC -gt 60) {
                            if ($isRussianOS) {
                                $diskHealth.Recommendations += "Высокая температура диска ($tempC°C)"
                            } else {
                                $diskHealth.Recommendations += "High disk temperature ($tempC°C)"
                            }
                            $diskHealth.HealthScore -= 10
                        }
                        
                        $smartDetails += "Temperature: ${tempC}°C"
                    }
                } catch {}
                
                try {
                    $smartAttributes = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_ATAPISmartData -ErrorAction SilentlyContinue | 
                                     Where-Object { $_.InstanceName -like "*$($disk.Index)*" } | 
                                     Select-Object -First 1
                    
                    if ($smartAttributes) {
                        $smartDetails += "AttributesAvailable: Yes"
                    } else {
                        $smartDetails += "AttributesAvailable: No"
                    }
                } catch {
                    $smartDetails += "SMART Access: Denied"
                }
                
                $diskHealth.SMART_Status += "$icon Disk $($disk.Index): $healthStatus"
                $diskHealth.Detailed_SMART += @{
                    Model = $disk.Model
                    Status = $healthStatus
                    SizeGB = [math]::Round($disk.Size/1GB,1)
                    Details = $smartDetails -join ", "
                    Index = $disk.Index
                }
            }
            
            try {
                $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
                $diskPartitions = Get-CimInstance Win32_DiskPartition
                $diskToPartition = Get-CimInstance Win32_LogicalDiskToPartition
                
                foreach ($physicalDisk in $physicalDisks) {
                    $mappedDrives = @()
                    
                    foreach ($partition in $diskPartitions | Where-Object { $_.DiskIndex -eq $physicalDisk.Index }) {
                        $associations = $diskToPartition | Where-Object { $_.Antecedent -like "*$($partition.DeviceID)*" }
                        
                        foreach ($assoc in $associations) {
                            $driveLetter = $assoc.Dependent.Split('=')[1].Replace('"','').Replace('}','')
                            $mappedDrives += $driveLetter
                        }
                    }
                    
                    if ($mappedDrives.Count -gt 0) {
                        $diskHealth.DiskMapping += @{
                            PhysicalDisk = "Disk $($physicalDisk.Index)"
                            DiskIndex = $physicalDisk.Index
                            Drives = $mappedDrives -join ", "
                            SizeGB = [math]::Round($physicalDisk.Size/1GB,1)
                        }
                    }
                }
            } catch {}
            
        } else {
            if ($isRussianOS) {
                $diskHealth.SMART_Status += "Информация SMART недоступна"
            } else {
                $diskHealth.SMART_Status += "SMART information not available"
            }
        }
        
        if ($isRussianOS) {
            Write-Info "SMART: $($diskHealth.Detailed_SMART.Count) дисков"
            Write-Info "Температура: $($diskHealth.Temperature)"
            Write-Success "Проверка дисков завершена"
        } else {
            Write-Info "SMART: $($diskHealth.Detailed_SMART.Count) disks"
            Write-Info "Temperature: $($diskHealth.Temperature)"
            Write-Success "Disk check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Info "  Информация о дисках ограничена"
        } else {
            Write-Info "  Disk information limited"
        }
    }
    
    return $diskHealth
}

function Discover-EventLogs {
    param([int]$Days = 7)
    
    if ($isRussianOS) {
        Write-Step "4/11" "Поиск журналов событий"
    } else {
        Write-Step "4/11" "Discovering event logs"
    }
    
    $logInfo = @{
        AvailableLogs = @()
        GroupedLogs = @{}
        Statistics = @{}
    }
    
    try {
        $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
        
        if (-not $allLogs) {
            if ($isRussianOS) {
                Write-Info "Не удалось получить список журналов"
            } else {
                Write-Info "Failed to get log list"
            }
            $logInfo.GroupedLogs = $StandardLogs
            return $logInfo
        }
        
        $availableLogs = @()
        $totalSizeMB = 0
        $totalRecords = 0
        
        foreach ($log in $allLogs) {
            try {
                $category = "Other"
                $logName = $log.LogName
                
                if ($logName -eq "System") { $category = "System" }
                elseif ($logName -eq "Application") { $category = "Application" }
                elseif ($logName -eq "Security") { $category = "Security" }
                elseif ($logName -eq "Setup") { $category = "Setup" }
                elseif ($logName -like "*Microsoft-Windows-*") { 
                    if ($logName -match "Microsoft-Windows-(.*?)/") {
                        $component = $matches[1]
                        
                        if ($component -like "*Kernel*") { $category = "Kernel" }
                        elseif ($component -like "*Storage*") { $category = "Storage" }
                        elseif ($component -like "*Network*") { $category = "Network" }
                        elseif ($component -like "*WMI*") { $category = "WMI" }
                        elseif ($component -like "*Security*") { $category = "Security" }
                        elseif ($component -like "*PowerShell*") { $category = "PowerShell" }
                        elseif ($component -like "*AppX*") { $category = "AppX" }
                        elseif ($component -like "*WindowsUpdate*") { $category = "WindowsUpdate" }
                        elseif ($component -like "*TaskScheduler*") { $category = "TaskScheduler" }
                        elseif ($component -like "*BitLocker*") { $category = "BitLocker" }
                        elseif ($component -like "*PrintService*") { $category = "PrintService" }
                        elseif ($component -like "*RemoteDesktop*") { $category = "RemoteDesktop" }
                        elseif ($component -like "*GroupPolicy*") { $category = "GroupPolicy" }
                        else { $category = $component }
                    }
                }
                elseif ($logName -eq "Windows PowerShell") { $category = "PowerShell" }
                
                $logSizeMB = [math]::Round($log.FileSize / 1MB, 2)
                $totalSizeMB += $logSizeMB
                $totalRecords += $log.RecordCount
                
                $availableLogs += [PSCustomObject]@{
                    LogName = $logName
                    Category = $category
                    IsEnabled = $log.IsEnabled
                    FileSizeMB = $logSizeMB
                    RecordCount = $log.RecordCount
                }
                
                if (-not $logInfo.GroupedLogs.ContainsKey($category)) {
                    $logInfo.GroupedLogs[$category] = @()
                }
                $logInfo.GroupedLogs[$category] += $logName
                
            } catch { continue }
        }
        
        $logInfo.AvailableLogs = $availableLogs
        $logInfo.Statistics = @{
            TotalLogs = $availableLogs.Count
            TotalCategories = $logInfo.GroupedLogs.Count
            TotalSizeMB = [math]::Round($totalSizeMB, 2)
            TotalRecords = $totalRecords
        }
        
        if ($isRussianOS) {
            Write-Info "Найдено журналов: $($availableLogs.Count)"
            Write-Info "Категорий: $($logInfo.GroupedLogs.Count)"
            Write-Info "Размер: $([math]::Round($totalSizeMB, 2)) MB"
            Write-Success "Поиск журналов завершен"
        } else {
            Write-Info "Found logs: $($availableLogs.Count)"
            Write-Info "Categories: $($logInfo.GroupedLogs.Count)"
            Write-Info "Size: $([math]::Round($totalSizeMB, 2)) MB"
            Write-Success "Log discovery completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка поиска журналов"
        } else {
            Write-Error "Error discovering logs"
        }
        $logInfo.GroupedLogs = $StandardLogs
    }
    
    return $logInfo
}

function Collect-AllEvents {
    param([int]$Days = 7, $LogGroups = $null)
    
    if ($isRussianOS) {
        Write-Step "5/11" "Сбор событий из журналов"
        Write-Info "⚠️  Только чтение данных, ничего не удаляется"
    } else {
        Write-Step "5/11" "Collecting events from logs"
        Write-Info "⚠️  Read-only, nothing is deleted"
    }
    
    $allEvents = @()
    
    $logsToScan = if ($LogGroups -and $LogGroups.GroupedLogs.Count -gt 0) {
        $LogGroups.GroupedLogs
    } else {
        $StandardLogs
    }
    
    $totalCategories = $logsToScan.Count
    $processedCategories = 0
    
    foreach ($category in $logsToScan.Keys) {
        $processedCategories++
        if ($isRussianOS) {
            Write-Info "Категория: $category ($processedCategories/$totalCategories)"
        } else {
            Write-Info "Category: $category ($processedCategories/$totalCategories)"
        }
        
        foreach ($logName in $logsToScan[$category]) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 200 -ErrorAction SilentlyContinue | 
                         Where-Object { 
                             $_.TimeCreated -ge (Get-Date).AddDays(-$Days) -and 
                             $_.Level -in @(1,2,3)
                         }
                
                if ($events -and $events.Count -gt 0) {
                    foreach ($event in $events) {
                        $cleanMessage = $event.Message -replace "`r`n", " | " -replace "`n", " | "
                        $cleanMessage = $cleanMessage -replace '[{}[\]\\""]', ''
                        $cleanMessage = $cleanMessage.Substring(0, [Math]::Min(250, $cleanMessage.Length))
                        
                        $allEvents += [PSCustomObject]@{
                            Category = $category
                            Log = $logName
                            Time = $event.TimeCreated
                            Level = $event.Level
                            LevelText = switch ($event.Level) {
                                1 { "CRITICAL" }
                                2 { "ERROR" }
                                3 { "WARNING" }
                                default { "INFO" }
                            }
                            Provider = $event.ProviderName
                            EventID = $event.Id
                            Task = $event.TaskDisplayName
                            Message = $cleanMessage
                            UserId = "USER_ANONYMIZED"
                            MachineName = "MACHINE_ANONYMIZED"
                        }
                    }
                    
                    if ($isRussianOS) {
                        Write-Info "  ✓ ${logName}: $($events.Count) событий"
                    } else {
                        Write-Info "  ✓ ${logName}: $($events.Count) events"
                    }
                } else {
                    if ($isRussianOS) {
                        Write-Info "  - ${logName}: нет событий уровня 1-3"
                    } else {
                        Write-Info "  - ${logName}: no level 1-3 events"
                    }
                }
                
            } catch {
                if ($isRussianOS) {
                    Write-Info "  ✗ ${logName}: недоступен"
                } else {
                    Write-Info "  ✗ ${logName}: unavailable"
                }
            }
        }
    }
    
    if ($isRussianOS) {
        Write-Info "Всего собрано событий: $($allEvents.Count)"
        Write-Success "Сбор событий завершен"
    } else {
        Write-Info "Total events collected: $($allEvents.Count)"
        Write-Success "Event collection completed"
    }
    
    return $allEvents
}

function Analyze-Events {
    param($Events)
    
    if ($isRussianOS) {
        Write-Step "6/11" "Анализ событий"
    } else {
        Write-Step "6/11" "Analyzing events"
    }
    
    if ($Events.Count -eq 0) {
        return @{
            AllEvents = @()
            Classified = @{}
            Statistics = @{}
            Flags = @{}
            EventPatterns = @{}
        }
    }
    
    if ($isRussianOS) {
        Write-Info "Анализирую $($Events.Count) событий..."
    } else {
        Write-Info "Analyzing $($Events.Count) events..."
    }
    
    $criticalCats = @("System", "Security", "Kernel", "Storage", "Disk", "NTFS", "Memory", "Driver", "Boot")
    $importantCats = @("Application", "Setup", "WMI", "Network", "DHCP", "DNS", "Firewall", "Defender")
    
    $stats = @{
        Total = $Events.Count
        Critical = ($Events | Where-Object { $_.Level -eq 1 }).Count
        Errors = ($Events | Where-Object { $_.Level -eq 2 }).Count
        Warnings = ($Events | Where-Object { $_.Level -eq 3 }).Count
    }
    
    $classified = @{
        Critical = $Events | Where-Object { $_.Level -eq 1 } | Sort-Object Time -Descending
        ImportantErrors = $Events | Where-Object { 
            $_.Level -eq 2 -and $_.Category -in $criticalCats 
        } | Sort-Object Time -Descending
        SystemErrors = $Events | Where-Object { 
            $_.Level -eq 2 -and $_.Category -in $importantCats 
        } | Sort-Object Time -Descending
        OtherErrors = $Events | Where-Object { 
            $_.Level -eq 2 -and $_.Category -notin $criticalCats -and $_.Category -notin $importantCats 
        } | Sort-Object Time -Descending
        ImportantWarnings = $Events | Where-Object { 
            $_.Level -eq 3 -and $_.Category -in $criticalCats 
        } | Sort-Object Time -Descending
        OtherWarnings = $Events | Where-Object { 
            $_.Level -eq 3 -and $_.Category -notin $criticalCats 
        } | Sort-Object Time -Descending
    }
    
    $eventPatterns = @{
        DiskErrors = $Events | Where-Object { 
            $_.EventID -in @(7, 11, 15, 52, 129, 549) -or 
            ($_.Message -match "disk" -or $_.Message -match "drive" -or $_.Message -match "storport")
        } | Sort-Object Time -Descending
        
        MemoryErrors = $Events | Where-Object { 
            $_.EventID -in @(2001, 2004, 2019) -or 
            ($_.Message -match "memory" -or $_.Message -match "pagefile")
        } | Sort-Object Time -Descending
        
        ServiceErrors = $Events | Where-Object { 
            $_.EventID -in @(7000, 7001, 7009, 7011, 7023, 7024, 7026, 7031, 7034) -or 
            $_.Provider -match "Service Control Manager"
        } | Sort-Object Time -Descending
        
        WMIErrors = $Events | Where-Object { 
            $_.Category -eq "WMI" -or 
            $_.Provider -match "WinMgmt" -or
            $_.EventID -in @(10, 13, 14, 15, 16)
        } | Sort-Object Time -Descending
        
        NetworkErrors = $Events | Where-Object { 
            $_.Category -eq "Network" -or
            $_.EventID -in @(1001, 1002, 1003, 1004, 1014, 1202) -or
            $_.Provider -match "Tcpip|NetBT|DNS|DHCP"
        } | Sort-Object Time -Descending
    }
    
    $flags = @{
        HasCriticalEvents = $classified.Critical.Count -gt 0
        HasImportantErrors = $classified.ImportantErrors.Count -gt 0
        TotalUniqueErrors = ($Events | Where-Object { $_.Level -in @(1,2) } | 
                           Group-Object @{Expression={ "$($_.EventID) - $($_.Provider)" }}).Count
        MostCommonError = if ($stats.Errors -gt 0) {
            $Events | Where-Object { $_.Level -eq 2 } | 
            Group-Object @{Expression={ "$($_.EventID) - $($_.Provider)" }} |
            Sort-Object Count -Descending | Select-Object -First 1
        } else { $null }
        
        HasDiskErrors = $eventPatterns.DiskErrors.Count -gt 0
        HasMemoryErrors = $eventPatterns.MemoryErrors.Count -gt 0
        HasServiceErrors = $eventPatterns.ServiceErrors.Count -gt 0
        HasWMIErrors = $eventPatterns.WMIErrors.Count -gt 0
        HasNetworkErrors = $eventPatterns.NetworkErrors.Count -gt 0
        
        DiskErrorCount = $eventPatterns.DiskErrors.Count
        MemoryErrorCount = $eventPatterns.MemoryErrors.Count
        ServiceErrorCount = $eventPatterns.ServiceErrors.Count
        WMIErrorCount = $eventPatterns.WMIErrors.Count
        NetworkErrorCount = $eventPatterns.NetworkErrors.Count
    }
    
    $timePatterns = @()
    $hourlyGroups = $Events | Where-Object { $_.Level -in @(1,2) } | 
                   Group-Object @{Expression={ $_.Time.Hour }} |
                   Sort-Object Count -Descending | Select-Object -First 3
    
    foreach ($hourGroup in $hourlyGroups) {
        $timePatterns += "Hour $($hourGroup.Name): $($hourGroup.Count) errors"
    }
    
    $flags.TimePatterns = $timePatterns
    
    if ($isRussianOS) {
        Write-Info "Анализ завершен:"
        Write-Info "  • Критических: $($classified.Critical.Count)"
        Write-Info "  • Ошибок: $($stats.Errors)"
        Write-Info "  • Ошибок дисков: $($flags.DiskErrorCount)"
        Write-Info "  • Ошибок памяти: $($flags.MemoryErrorCount)"
        Write-Success "Анализ событий завершен"
    } else {
        Write-Info "Analysis completed:"
        Write-Info "  • Critical: $($classified.Critical.Count)"
        Write-Info "  • Errors: $($stats.Errors)"
        Write-Info "  • Disk errors: $($flags.DiskErrorCount)"
        Write-Info "  • Memory errors: $($flags.MemoryErrorCount)"
        Write-Success "Event analysis completed"
    }
    
    return @{
        AllEvents = $Events
        Classified = $classified
        Statistics = $stats
        Flags = $flags
        EventPatterns = $eventPatterns
        TimePatterns = $timePatterns
    }
}

function Check-GhostDevices {
    if ($isRussianOS) {
        Write-Step "7/11" "Проверка отключенных устройств"
    } else {
        Write-Step "7/11" "Checking disabled devices"
    }
    
    $ghostInfo = @{
        TotalDevices = 0
        DisabledDevices = 0
        ProblemDevices = 0
        GhostDevices = @()
        Statistics = @{}
    }
    
    try {
        $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue
        
        if ($allDevices) {
            $ghostInfo.TotalDevices = $allDevices.Count
            
            $disabledDevices = $allDevices | Where-Object { 
                $_.Status -eq "Error" -or 
                $_.Status -eq "Degraded" -or
                $_.Problem -ne $null
            }
            
            $ghostInfo.DisabledDevices = $disabledDevices.Count
            $ghostInfo.ProblemDevices = ($allDevices | Where-Object { $_.Problem -ne $null }).Count
            
            $deviceCategories = @{}
            foreach ($device in $disabledDevices | Select-Object -First 10) {
                $class = if ($device.Class) { $device.Class } else { "Unknown" }
                
                if (-not $deviceCategories.ContainsKey($class)) {
                    $deviceCategories[$class] = 0
                }
                $deviceCategories[$class]++
            }
            
            foreach ($category in $deviceCategories.Keys) {
                $ghostInfo.GhostDevices += [PSCustomObject]@{
                    Category = $category
                    Count = $deviceCategories[$category]
                    Status = "Disabled/Problem"
                }
            }
            
            $ghostInfo.Statistics = @{
                TotalByStatus = ($allDevices | Group-Object Status | ForEach-Object { 
                    "$($_.Name): $($_.Count)" 
                }) -join ", "
                HasManyGhosts = $ghostInfo.DisabledDevices -gt 20
                CommonProblem = if ($deviceCategories.Count -gt 0) { 
                    ($deviceCategories.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key 
                } else { "None" }
            }
        }
        
        if ($isRussianOS) {
            Write-Info "Всего устройств: $($ghostInfo.TotalDevices)"
            Write-Info "Отключенных/проблемных: $($ghostInfo.DisabledDevices)"
            Write-Success "Проверка устройств завершена"
        } else {
            Write-Info "Total devices: $($ghostInfo.TotalDevices)"
            Write-Info "Disabled/problem devices: $($ghostInfo.DisabledDevices)"
            Write-Success "Device check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Info "Информация об устройствах ограничена"
        } else {
            Write-Info "Device information limited"
        }
    }
    
    return $ghostInfo
}

function Check-Services {
    if ($isRussianOS) {
        Write-Step "8/11" "Проверка служб"
    } else {
        Write-Step "8/11" "Checking services"
    }
    
    $services = @{
        Total = 0
        Running = 0
        Stopped = 0
        Problematic = @()
        Statistics = @{}
    }
    
    try {
        $allServices = Get-Service -ErrorAction Stop
        $services.Total = $allServices.Count
        $services.Running = ($allServices | Where-Object { $_.Status -eq 'Running' }).Count
        $services.Stopped = ($allServices | Where-Object { $_.Status -eq 'Stopped' }).Count
        
        $problemServices = $allServices | 
            Where-Object { 
                ($_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic') -or
                ($_.Status -eq 'Running' -and $_.StartType -eq 'Disabled')
            } |
            Select-Object DisplayName, Name, Status, StartType, @{
                N="Problem";E={
                    if ($_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic') { 
                        if ($isRussianOS) { "Авто, но остановлена" } else { "Auto but stopped" }
                    }
                    elseif ($_.Status -eq 'Running' -and $_.StartType -eq 'Disabled') { 
                        if ($isRussianOS) { "Запущена, но отключена" } else { "Running but disabled" }
                    }
                    else { 
                        if ($isRussianOS) { "Норма" } else { "Normal" }
                    }
                }
            } |
            Sort-Object DisplayName
        
        $services.Problematic = $problemServices
        
        $services.Statistics = @{
            CriticalServices = ($allServices | Where-Object { 
                $_.Name -in @("Winmgmt", "EventLog", "DcomLaunch", "RpcSs", "LSASS")
            }).Count
            StoppedCritical = ($allServices | Where-Object { 
                $_.Name -in @("Winmgmt", "EventLog", "DcomLaunch", "RpcSs", "LSASS") -and $_.Status -ne 'Running'
            }).Count
        }
        
        if ($isRussianOS) {
            Write-Info "Всего служб: $($services.Total)"
            Write-Info "Запущено: $($services.Running)"
            Write-Info "Остановлено: $($services.Stopped)"
            Write-Info "Проблемных: $($services.Problematic.Count)"
            Write-Success "Проверка служб завершена"
        } else {
            Write-Info "Total services: $($services.Total)"
            Write-Info "Running: $($services.Running)"
            Write-Info "Stopped: $($services.Stopped)"
            Write-Info "Problematic: $($services.Problematic.Count)"
            Write-Success "Service check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка проверки служб"
        } else {
            Write-Error "Error checking services"
        }
    }
    
    return $services
}

function Check-Disks {
    if ($isRussianOS) {
        Write-Step "9/11" "Проверка дисков"
    } else {
        Write-Step "9/11" "Checking disks"
    }
    
    $diskInfo = @{
        LogicalDisks = @()
        PhysicalDisks = @()
        Statistics = @{}
    }
    
    try {
        $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        
        foreach ($disk in $logicalDisks) {
            $freePercent = if ($disk.Size -gt 0) { 
                [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) 
            } else { 0 }
            
            $status = if ($freePercent -lt 10) { "CRITICAL" }
                     elseif ($freePercent -lt 20) { "WARNING" }
                     else { "OK" }
            
            $diskInfo.LogicalDisks += [PSCustomObject]@{
                Drive = $disk.DeviceID
                Label = $disk.VolumeName
                TotalGB = [math]::Round($disk.Size / 1GB, 1)
                FreeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
                UsedGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 1)
                FreePercent = $freePercent
                Status = $status
                Type = if ($disk.DriveType -eq 3) { "Local Disk" } else { "Other" }
            }
        }
        
        try {
            $physicalDisks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
            if ($physicalDisks) {
                foreach ($disk in $physicalDisks) {
                    $diskInfo.PhysicalDisks += [PSCustomObject]@{
                        Model = $disk.Model
                        SizeGB = [math]::Round($disk.Size / 1GB, 1)
                        Interface = $disk.InterfaceType
                        Status = $disk.Status
                    }
                }
            }
        } catch {}
        
        $diskInfo.Statistics = @{
            TotalDisks = $logicalDisks.Count
            TotalSpaceGB = [math]::Round(($logicalDisks | Measure-Object -Property Size -Sum).Sum / 1GB, 1)
            FreeSpaceGB = [math]::Round(($logicalDisks | Measure-Object -Property FreeSpace -Sum).Sum / 1GB, 1)
            WarningDisks = ($diskInfo.LogicalDisks | Where-Object { $_.FreePercent -lt 20 }).Count
            CriticalDisks = ($diskInfo.LogicalDisks | Where-Object { $_.FreePercent -lt 10 }).Count
        }
        
        if ($isRussianOS) {
            Write-Info "Логических дисков: $($diskInfo.LogicalDisks.Count)"
            Write-Info "Предупреждений: $($diskInfo.Statistics.WarningDisks)"
            Write-Success "Проверка дисков завершена"
        } else {
            Write-Info "Logical disks: $($diskInfo.LogicalDisks.Count)"
            Write-Info "Warnings: $($diskInfo.Statistics.WarningDisks)"
            Write-Success "Disk check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка проверки дисков"
        } else {
            Write-Error "Error checking disks"
        }
    }
    
    return $diskInfo
}

function Check-HiddenTasks {
    if ($isRussianOS) {
        Write-Step "10/11" "Проверка скрытых задач"
    } else {
        Write-Step "10/11" "Checking hidden tasks"
    }
    
    $hiddenTasks = @{
        AllHiddenTasks = @()
        SuspiciousTasks = @()
        FrequentTasks = @()
        TopFrequentTasks = @()
        Statistics = @{}
    }
    
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        
        $hiddenTaskList = @()
        foreach ($task in $allTasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $taskDefinition = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                
                if ($taskDefinition -and $taskInfo) {
                    $isHidden = $taskDefinition.Settings.Hidden
                    
                    $actions = $taskDefinition.Actions
                    $executablePath = ""
                    $suspiciousPath = $false
                    
                    foreach ($action in $actions) {
                        if ($action.Execute -and $action.Execute -ne "") {
                            $executablePath = $action.Execute
                            if ($executablePath -match "\\AppData\\Local\\Temp\\.*\.(exe|bat|ps1|vbs|js)" -or 
                                $executablePath -match "\\Temp\\.*\.(exe|bat|ps1|vbs|js)" -or
                                $executablePath -match "\\Windows\\Temp\\.*\.(exe|bat|ps1|vbs|js)") {
                                $suspiciousPath = $true
                            }
                            break
                        }
                    }
                    
                    $triggers = $taskDefinition.Triggers
                    $frequentTrigger = $false
                    
                    foreach ($trigger in $triggers) {
                        if ($trigger.Repetition -and $trigger.Repetition.Interval) {
                            $interval = $trigger.Repetition.Interval
                            if ($interval -match "PT(1[0-5]M|[1-9]M)") {
                                $frequentTrigger = $true
                            }
                        }
                    }
                    
                    if ($isHidden -or $suspiciousPath -or $frequentTrigger) {
                        $hiddenTaskList += [PSCustomObject]@{
                            TaskName = $task.TaskName
                            TaskPath = $task.TaskPath
                            IsHidden = $isHidden
                            LastRunTime = if ($taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
                            NextRunTime = if ($taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm") } else { "Not scheduled" }
                            HasFrequentTrigger = $frequentTrigger
                        }
                        
                        if ($suspiciousPath) {
                            $hiddenTasks.SuspiciousTasks += [PSCustomObject]@{
                                TaskName = $task.TaskName
                                Reason = if ($isRussianOS) { "Запуск из временной папки" } else { "Runs from temp folder" }
                            }
                        }
                        
                        if ($frequentTrigger) {
                            $hiddenTasks.FrequentTasks += [PSCustomObject]@{
                                TaskName = $task.TaskName
                                Reason = if ($isRussianOS) { "Частый запуск (каждые 15 мин или чаще)" } else { "Frequent execution (every 15 min or more often)" }
                            }
                        }
                    }
                }
            } catch { continue }
        }
        
        $hiddenTasks.AllHiddenTasks = $hiddenTaskList
        
        # Анализ частоты запуска задач
        try {
            $taskEvents = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue |
                         Where-Object { $_.TimeCreated -ge (Get-Date).AddDays(-1) }
            
            if ($taskEvents.Count -gt 0) {
                $taskFrequency = @{}
                
                foreach ($event in $taskEvents) {
                    if ($event.Message -match "TaskId:\s*\{([A-F0-9\-]+)\}") {
                        $taskId = $matches[1]
                        if (-not $taskFrequency.ContainsKey($taskId)) {
                            $taskFrequency[$taskId] = 0
                        }
                        $taskFrequency[$taskId]++
                    }
                }
                
                $topTasks = $taskFrequency.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3
                
                if ($topTasks.Count -gt 0) {
                    $hiddenTasks.TopFrequentTasks = @()
                    $i = 1
                    foreach ($task in $topTasks) {
                        $taskName = if ($task.Key.Length -gt 8) { 
                            "Task_" + $task.Key.Substring(0, 8) + "..." 
                        } else { 
                            "Task_" + $task.Key 
                        }
                        
                        $hiddenTasks.TopFrequentTasks += [PSCustomObject]@{
                            Rank = $i
                            TaskID = $taskName
                            Executions = $task.Value
                            Period = "last 24h"
                            Note = if ($task.Value -gt 100) { "VERY FREQUENT - May cause system lag" } 
                                   elseif ($task.Value -gt 50) { "FREQUENT - Monitor impact" }
                                   else { "Normal frequency" }
                        }
                        $i++
                    }
                }
            }
        } catch {}
        
        $hiddenTasks.Statistics = @{
            TotalTasks = $allTasks.Count
            HiddenTasks = ($hiddenTaskList | Where-Object { $_.IsHidden -eq $true }).Count
            SuspiciousTasks = $hiddenTasks.SuspiciousTasks.Count
            FrequentTasks = $hiddenTasks.FrequentTasks.Count
        }
        
        if ($isRussianOS) {
            Write-Info "Всего задач: $($allTasks.Count)"
            Write-Info "Скрытых задач: $($hiddenTasks.Statistics.HiddenTasks)"
            if ($hiddenTasks.TopFrequentTasks.Count -gt 0) {
                Write-Info "Частых задач: $($hiddenTasks.TopFrequentTasks.Count)"
            }
            Write-Success "Проверка задач завершена"
        } else {
            Write-Info "Total tasks: $($allTasks.Count)"
            Write-Info "Hidden tasks: $($hiddenTasks.Statistics.HiddenTasks)"
            if ($hiddenTasks.TopFrequentTasks.Count -gt 0) {
                Write-Info "Frequent tasks: $($hiddenTasks.TopFrequentTasks.Count)"
            }
            Write-Success "Task check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка проверки задач"
        } else {
            Write-Error "Error checking tasks"
        }
    }
    
    return $hiddenTasks
}

function Check-Security {
    if ($isRussianOS) {
        Write-Step "11/11" "Проверка безопасности"
    } else {
        Write-Step "11/11" "Checking security"
    }
    
    $security = @{
        Antivirus = @()
        Defender = @{}
        Firewall = @{}
        BootSecurity = @{}
    }
    
    try {
        $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($avProducts) {
            foreach ($av in $avProducts) {
                $security.Antivirus += @{
                    Name = $av.displayName
                    State = if ($av.productState -eq 397568) { 
                        if ($isRussianOS) { "Включен и обновлен" } else { "Enabled & Updated" }
                    }
                    elseif ($av.productState -eq 262144) { 
                        if ($isRussianOS) { "Отключен" } else { "Disabled" }
                    }
                    else { 
                        if ($isRussianOS) { "Неизвестно" } else { "Unknown" }
                    }
                }
            }
        }
        
        try {
            $defStatus = Get-MpComputerStatus -ErrorAction Stop
            $security.Defender = @{
                Enabled = $defStatus.AntivirusEnabled
                RealTime = $defStatus.RealTimeProtectionEnabled
                LastScan = if ($defStatus.LastFullScanTime) { $defStatus.LastFullScanTime.ToString("yyyy-MM-dd") } else { 
                    if ($isRussianOS) { "Никогда" } else { "Never" }
                }
            }
        } catch {
            $security.Defender = @{ Status = if ($isRussianOS) { "Недоступно" } else { "Not Available" } }
        }
        
        try {
            $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
            $security.Firewall = @{
                Domain = ($fwProfiles | Where-Object { $_.Name -eq "Domain" }).Enabled
                Private = ($fwProfiles | Where-Object { $_.Name -eq "Private" }).Enabled
                Public = ($fwProfiles | Where-Object { $_.Name -eq "Public" }).Enabled
            }
        } catch {
            $security.Firewall = @{ Status = if ($isRussianOS) { "Недоступно" } else { "Not Available" } }
        }
        
        $bootSecurityData = @{}
        
        try {
            $secureBootStatus = Confirm-SecureBootUEFI
            $bootSecurityData.SecureBoot = $secureBootStatus
        } catch {
            $bootSecurityData.SecureBoot = $false
        }
        
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $bootSecurityData.TPM = $tpm.TpmPresent
        } catch {
            $bootSecurityData.TPM = $false
        }
        
        $security.BootSecurity = $bootSecurityData
        
        if ($isRussianOS) {
            Write-Info "Антивирусов: $($security.Antivirus.Count)"
            Write-Info "Defender: $(if($security.Defender.Enabled){'Активен'}else{'Неактивен'})"
            Write-Success "Проверка безопасности завершена"
        } else {
            Write-Info "Antiviruses: $($security.Antivirus.Count)"
            Write-Info "Defender: $(if($security.Defender.Enabled){'Active'}else{'Inactive'})"
            Write-Success "Security check completed"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка проверки безопасности"
        } else {
            Write-Error "Error checking security"
        }
    }
    
    return $security
}

function Create-Reports {
    param(
        $SystemInfo,
        $EventAnalysis,
        $LogInfo,
        $Services,
        $Disks,
        $DiskHealth,
        $Temperatures,
        $HiddenTasks,
        $Security,
        $GhostDevices,
        $Days
    )
    
    if ($isRussianOS) {
        Write-Step "12/12" "Создание отчетов"
    } else {
        Write-Step "12/12" "Creating reports"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmm"
    $reports = @{
        AIReport = $null
        BriefReport = $null
    }
    
    try {
        $aiReport = "# WINDOWS DIAGNOSTICS REPORT - COMPLETE SCAN`n"
        $aiReport += "## INSTRUCTIONS FOR AI ASSISTANT:`n"
        $aiReport += "# You are analyzing a detailed diagnostic report.`n"
        $aiReport += "# The user is likely a beginner or intermediate user.`n"
        $aiReport += "# Explain technical issues in simple terms.`n"
        $aiReport += "# Focus on hardware vs software issues.`n"
        $aiReport += "# Rate criticality from 1-10.`n"
        $aiReport += "#`n"
        $aiReport += "Version: $ScriptVersion | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"
        $aiReport += "Period: $Days days | Logs scanned: $($LogInfo.Statistics.TotalLogs)`n"
        $aiReport += "Computer: $($SystemInfo.ComputerName) | Privacy: ANONYMIZED`n"
        $aiReport += "=" * 70 + "`n`n"
        
        # System Information
        $aiReport += "## SYSTEM INFORMATION`n"
        $aiReport += "Computer: $($SystemInfo.ComputerName)`n"
        $aiReport += "Windows: $($SystemInfo.WindowsName) ($($SystemInfo.Version))`n"
        $aiReport += "Build: $($SystemInfo.Build) | Architecture: $($SystemInfo.Architecture)`n"
        $aiReport += "CPU: $($SystemInfo.CPU) ($($SystemInfo.CPU_Cores) cores, $($SystemInfo.CPU_Threads) threads)`n"
        $aiReport += "BIOS: $($SystemInfo.BIOS)`n"
        $aiReport += "BIOS Date: $($SystemInfo.BIOS_Date)`n"
        $aiReport += "RAM: $($SystemInfo.TotalRAM_GB) GB total | $($SystemInfo.UsedRAM_GB) GB used | $($SystemInfo.AvailableRAM_GB) GB available ($($SystemInfo.RAMUsagePercent)% usage)`n"
        $aiReport += "Hardware Reserved RAM: ~$($SystemInfo.HardwareReservedRAM_GB) GB`n"
        $aiReport += "Uptime: $($SystemInfo.UptimeDays) days | Last boot: $($SystemInfo.LastBoot)`n"
        $aiReport += "Disks: $($SystemInfo.Disks)`n"
        $aiReport += "`n"
        
        # Temperatures
        $aiReport += "## HARDWARE TEMPERATURES`n"
        if ($Temperatures.CPU.Temperature -ne "N/A") {
            $aiReport += "CPU: $($Temperatures.CPU.Temperature)°C [$($Temperatures.CPU.Status)]`n"
        } else {
            $aiReport += "CPU: Temperature data not available`n"
        }
        
        if ($Temperatures.Warnings.Count -gt 0) {
            $aiReport += "`n### TEMPERATURE WARNINGS`n"
            foreach ($warning in $Temperatures.Warnings) {
                $aiReport += "⚠️ $warning`n"
            }
        }
        $aiReport += "`n"
        
        # Event Logs
        $aiReport += "## EVENT LOGS SCANNED`n"
        $aiReport += "Total logs: $($LogInfo.Statistics.TotalLogs)`n"
        $aiReport += "Categories: $($LogInfo.Statistics.TotalCategories)`n"
        $aiReport += "Total size: $($LogInfo.Statistics.TotalSizeMB) MB`n"
        $aiReport += "`n"
        
        # Event Statistics
        $stats = $EventAnalysis.Statistics
        $aiReport += "## EVENT STATISTICS & PATTERNS`n"
        $aiReport += "Total events: $($stats.Total)`n"
        $aiReport += "Critical: $($stats.Critical) | Errors: $($stats.Errors) | Warnings: $($stats.Warnings)`n"
        $aiReport += "Unique error types: $($EventAnalysis.Flags.TotalUniqueErrors)`n"
        $aiReport += "`n"
        
        # Error Patterns
        $aiReport += "### ERROR PATTERNS DETECTED`n"
        if ($EventAnalysis.Flags.HasDiskErrors) {
            $aiReport += "🔴 DISK ERRORS: $($EventAnalysis.Flags.DiskErrorCount) events - Possible disk failure/storage issues`n"
        }
        if ($EventAnalysis.Flags.HasMemoryErrors) {
            $aiReport += "🟡 MEMORY ERRORS: $($EventAnalysis.Flags.MemoryErrorCount) events - RAM/pagefile issues`n"
        }
        if ($EventAnalysis.Flags.HasServiceErrors) {
            $aiReport += "🟠 SERVICE ERRORS: $($EventAnalysis.Flags.ServiceErrorCount) events - Service failures`n"
        }
        if ($EventAnalysis.Flags.HasWMIErrors) {
            $aiReport += "🔵 WMI ERRORS: $($EventAnalysis.Flags.WMIErrorCount) events - WMI issues`n"
        }
        $aiReport += "`n"
        
        # Time Patterns
        if ($EventAnalysis.TimePatterns.Count -gt 0) {
            $aiReport += "### ERROR TIME PATTERNS`n"
            foreach ($pattern in $EventAnalysis.TimePatterns) {
                $aiReport += "• $pattern`n"
            }
            $aiReport += "`n"
        }
        
        # Critical Events
        $criticalEvents = $EventAnalysis.Classified.Critical
        if ($criticalEvents.Count -gt 0) {
            $aiReport += "## CRITICAL EVENTS (first 5)`n"
            $i = 1
            foreach ($event in $criticalEvents | Select-Object -First 5) {
                $aiReport += "$i. [$($event.Time.ToString('yyyy-MM-dd HH:mm'))] $($event.Provider) ($($event.EventID))`n"
                $aiReport += "   $($event.Message)`n"
                $i++
            }
            $aiReport += "`n"
        }
        
        # Most Frequent Errors WITH CONFIDENCE MARKERS
        $errorGroups = $EventAnalysis.AllEvents | Where-Object { $_.Level -eq 2 } | 
                      Group-Object @{Expression={ "$($_.EventID) - $($_.Provider) [$($_.Category)]" }} |
                      Sort-Object Count -Descending | Select-Object -First 8
        
        if ($errorGroups.Count -gt 0) {
            $aiReport += "## MOST FREQUENT ERRORS (with confidence markers)`n"
            $i = 1
            foreach ($group in $errorGroups) {
                $lastEvent = $group.Group | Sort-Object Time -Descending | Select-Object -First 1
                $lastEventID = $lastEvent.EventID
                
                $aiReport += "$i. **$($group.Name)** (x$($group.Count) times)`n"
                $aiReport += "   Last occurrence: $($lastEvent.Time.ToString('yyyy-MM-dd HH:mm'))`n"
                
                # Confidence markers for common errors
                $insight = ""
                $confidence = ""
                
                switch ($lastEventID) {
                    { $_ -in @(7, 11, 15, 52) } {
                        $insight = "⚠️ **HARDWARE ISSUE**: Disk bad sectors likely"
                        $confidence = "(ID ${lastEventID}: High probability of physical disk media damage)"
                    }
                    { $_ -eq 129 } {
                        $insight = "⚠️ **HARDWARE ISSUE**: Disk timeout/connection problem"
                        $confidence = "(ID 129: Storage device not responding, check cables/controller)"
                    }
                    { $_ -eq 549 } {
                        $insight = "⚠️ **HARDWARE ISSUE**: StorPort controller failure"
                        $confidence = "(ID 549: Storage port driver error, often hardware-related)"
                    }
                    { $_ -eq 507 } {
                        $insight = "⚠️ **HARDWARE ISSUE**: Disk failure imminent"
                        $confidence = "(ID 507: High probability of physical disk sectors failure)"
                    }
                    { $_ -in @(2001, 2004, 2019) } {
                        $insight = "⚠️ **MEMORY ISSUE**: RAM/pagefile problems"
                        $confidence = "(ID ${lastEventID}: Memory management failure, check RAM health)"
                    }
                    { $_ -in @(7000, 7001, 7009, 7011) } {
                        $insight = "⚠️ **SERVICE FAILURE**: Service failed to start"
                        $confidence = "(ID ${lastEventID}: Service control manager error, check dependencies)"
                    }
                    { $_ -eq 5858 } {
                        $insight = "⚠️ **WMI ISSUE**: Repository corruption likely"
                        $confidence = "(ID 5858: WMI provider failure, often malware or system corruption)"
                    }
                    default {
                        $insight = "Monitor frequency and check system stability"
                        $confidence = "(ID ${lastEventID}: General system error)"
                    }
                }
                
                $aiReport += "   $insight`n"
                $aiReport += "   $confidence`n"
                $i++
            }
            $aiReport += "`n"
        }
        
        # Ghost Devices
        $aiReport += "## GHOST DEVICES ANALYSIS`n"
        $aiReport += "Total devices detected: $($GhostDevices.TotalDevices)`n"
        $aiReport += "Disabled/problem devices: $($GhostDevices.DisabledDevices)`n"
        if ($GhostDevices.DisabledDevices -gt 20) {
            $aiReport += "⚠️ **HIGH GHOST DEVICE COUNT**: $($GhostDevices.DisabledDevices) disabled devices`n"
            $aiReport += "This many ghost devices can cause driver conflicts and system instability.`n"
        }
        if ($GhostDevices.GhostDevices.Count -gt 0) {
            $aiReport += "**Problem categories:**`n"
            foreach ($device in $GhostDevices.GhostDevices) {
                $aiReport += "- $($device.Category): $($device.Count) devices`n"
            }
        }
        $aiReport += "`n"
        
        # Task Frequency Analysis
        $aiReport += "## TASK FREQUENCY ANALYSIS`n"
        if ($HiddenTasks.TopFrequentTasks.Count -gt 0) {
            $aiReport += "**Top 3 most frequently executed tasks (last 24h):**`n"
            foreach ($task in $HiddenTasks.TopFrequentTasks) {
                $aiReport += "$($task.Rank). **$($task.TaskID)**: $($task.Executions) executions`n"
                $aiReport += "   Note: $($task.Note)`n"
            }
            $aiReport += "`n**Note:** Tasks running 50+ times per day may cause system lag.`n"
        } else {
            $aiReport += "No frequent task data available`n"
        }
        $aiReport += "`n"
        
        # Disks
        $aiReport += "## DISK STATUS`n"
        foreach ($disk in $Disks.LogicalDisks) {
            $icon = if ($disk.FreePercent -lt 10) {"🔴"} elseif ($disk.FreePercent -lt 20) {"🟡"} else {"🟢"}
            $aiReport += "$icon $($disk.Drive): $($disk.FreeGB) GB free of $($disk.TotalGB) GB ($($disk.FreePercent)%) [$($disk.Status)]`n"
        }
        $aiReport += "`n"
        
        # Disk Health
        $aiReport += "## DISK HEALTH - SMART ANALYSIS`n"
        if ($DiskHealth.Detailed_SMART.Count -gt 0) {
            foreach ($status in $DiskHealth.SMART_Status) {
                $aiReport += "$status`n"
            }
            $aiReport += "`n"
        } else {
            $aiReport += "SMART information not available`n"
            $aiReport += "**Note**: SMART unavailable could indicate:`n"
            $aiReport += "1. SSD with proprietary controller`n"
            $aiReport += "2. Insufficient permissions`n"
            $aiReport += "3. Driver/controller issues`n"
        }
        $aiReport += "`n"
        
        # Hidden Tasks
        $aiReport += "## HIDDEN SCHEDULED TASKS`n"
        $aiReport += "Total tasks found: $($HiddenTasks.Statistics.TotalTasks)`n"
        $aiReport += "Hidden tasks: $($HiddenTasks.Statistics.HiddenTasks)`n"
        $aiReport += "Suspicious tasks: $($HiddenTasks.Statistics.SuspiciousTasks)`n"
        $aiReport += "Frequently running tasks: $($HiddenTasks.Statistics.FrequentTasks)`n"
        $aiReport += "`n"
        
        # Services
        if ($Services.Problematic.Count -gt 0) {
            $aiReport += "## PROBLEMATIC SERVICES`n"
            foreach ($service in $Services.Problematic | Select-Object -First 5) {
                $aiReport += "- $($service.DisplayName): $($service.Status) (should be $($service.StartType))`n"
            }
            $aiReport += "`n"
        }
        
        # Security
        $aiReport += "## SECURITY STATUS`n"
        if ($Security.Antivirus.Count -gt 0) {
            foreach ($av in $Security.Antivirus) {
                $aiReport += "Antivirus: $($av.Name) [$($av.State)]`n"
            }
        }
        $aiReport += "Windows Defender: $(if($Security.Defender.Enabled){'Active'}else{'Inactive'})`n"
        $aiReport += "Real-time protection: $(if($Security.Defender.RealTime){'Enabled'}else{'Disabled'})`n"
        $aiReport += "Firewall (Public): $(if($Security.Firewall.Public){'Enabled'}else{'Disabled'})`n"
        $aiReport += "Secure Boot: $(if($Security.BootSecurity.SecureBoot){'Enabled'}else{'Disabled'})`n"
        $aiReport += "TPM: $(if($Security.BootSecurity.TPM){'Present'}else{'Not present'})`n"
        $aiReport += "`n"
        
        # Health Assessment
        $healthScore = 100
        
        if ($Temperatures.CPU.Temperature -ne "N/A" -and $Temperatures.CPU.Temperature -gt 75) {
            $healthScore -= 15
        }
        
        $healthScore -= $stats.Critical * 20
        $healthScore -= [math]::Min($stats.Errors / 5, 40)
        $healthScore -= ($Disks.LogicalDisks | Where-Object { $_.FreePercent -lt 10 }).Count * 10
        $healthScore -= $Services.Problematic.Count * 5
        
        if ($GhostDevices.DisabledDevices -gt 20) {
            $healthScore -= 10
        }
        
        $healthScore -= $HiddenTasks.Statistics.SuspiciousTasks * 8
        $healthScore -= $HiddenTasks.Statistics.FrequentTasks * 5
        
        if (-not $Security.Defender.Enabled) { $healthScore -= 15 }
        if (-not $Security.Firewall.Public) { $healthScore -= 10 }
        
        $healthScore -= (100 - $DiskHealth.HealthScore) / 2
        
        if ($SystemInfo.RAMUsagePercent -gt 85) {
            $healthScore -= 10
        } elseif ($SystemInfo.RAMUsagePercent -gt 70) {
            $healthScore -= 5
        }
        
        $healthScore = [math]::Max(0, [math]::Round($healthScore))
        
        $aiReport += "## HEALTH ASSESSMENT`n"
        $aiReport += "**Overall Score: $healthScore/100**`n"
        
        if ($healthScore -ge 80) {
            $aiReport += "**Status: EXCELLENT** - System is in great condition.`n"
        } elseif ($healthScore -ge 65) {
            $aiReport += "**Status: GOOD** - Some issues detected but system is generally stable.`n"
        } elseif ($healthScore -ge 50) {
            $aiReport += "**Status: FAIR** - Multiple problems need attention.`n"
        } elseif ($healthScore -ge 30) {
            $aiReport += "**Status: POOR** - Serious issues present.`n"
        } else {
            $aiReport += "**Status: CRITICAL** - System is failing.`n"
        }
        
        $aiReport += "`n"
        
        # Hardware vs Software
        $aiReport += "### HARDWARE VS SOFTWARE ANALYSIS`n"
        
        $hardwareIssues = @()
        $softwareIssues = @()
        
        if ($Temperatures.Warnings.Count -gt 0) { $hardwareIssues += "Temperature issues" }
        if ($DiskHealth.HealthScore -lt 70) { $hardwareIssues += "Disk health problems" }
        if ($EventAnalysis.Flags.HasDiskErrors -and $EventAnalysis.Flags.DiskErrorCount -gt 5) { $hardwareIssues += "Disk errors (hardware likely)" }
        
        if ($HiddenTasks.Statistics.SuspiciousTasks -gt 0) { $softwareIssues += "Suspicious tasks" }
        if ($HiddenTasks.Statistics.FrequentTasks -gt 0) { $softwareIssues += "Frequent tasks" }
        if ($EventAnalysis.Flags.HasWMIErrors) { $softwareIssues += "WMI errors" }
        if ($Services.Problematic.Count -gt 3) { $softwareIssues += "Service failures" }
        if (-not $Security.Defender.Enabled) { $softwareIssues += "Security disabled" }
        if ($GhostDevices.DisabledDevices -gt 10) { $softwareIssues += "Ghost devices" }
        
        if ($hardwareIssues.Count -gt 0) {
            $aiReport += "**Hardware Issues Detected ($($hardwareIssues.Count)):**`n"
            foreach ($issue in $hardwareIssues) {
                $aiReport += "• $issue`n"
            }
            $aiReport += "**Recommendation:** Consider hardware diagnostics/repair.`n"
        }
        
        if ($softwareIssues.Count -gt 0) {
            $aiReport += "**Software Issues Detected ($($softwareIssues.Count)):**`n"
            foreach ($issue in $softwareIssues) {
                $aiReport += "• $issue`n"
            }
            $aiReport += "**Recommendation:** Software cleanup, updates, configuration.`n"
        }
        
        $aiReport += "`n"
        
        # Recommendations
        $aiReport += "## RECOMMENDATIONS`n"
        
        if ($healthScore -lt 50) {
            $aiReport += "**PRIORITY 1 - IMMEDIATE ACTION REQUIRED:**`n"
            if ($DiskHealth.HealthScore -lt 50) {
                $aiReport += "1. **BACKUP DATA IMMEDIATELY** - Disk failure imminent`n"
            }
            if ($stats.Critical -gt 0) {
                $aiReport += "2. **RESOLVE CRITICAL EVENTS** ($($stats.Critical) found)`n"
            }
            $aiReport += "`n"
        }
        
        if ($healthScore -lt 70) {
            $aiReport += "**PRIORITY 2 - IMPORTANT FIXES:**`n"
            if ($HiddenTasks.Statistics.SuspiciousTasks -gt 0) {
                $aiReport += "1. **CHECK SUSPICIOUS TASKS** ($($HiddenTasks.Statistics.SuspiciousTasks) found)`n"
            }
            if (($Disks.LogicalDisks | Where-Object { $_.FreePercent -lt 15 }).Count -gt 0) {
                $aiReport += "2. **FREE UP DISK SPACE**`n"
            }
            if ($EventAnalysis.Flags.HasDiskErrors) {
                $aiReport += "3. **RUN DISK DIAGNOSTICS**`n"
            }
            if ($Services.Problematic.Count -gt 0) {
                $aiReport += "4. **FIX SERVICES** ($($Services.Problematic.Count) services)`n"
            }
            $aiReport += "`n"
        }
        
        $aiReport += "**PRIORITY 3 - MAINTENANCE:**`n"
        if (-not $Security.Defender.Enabled) {
            $aiReport += "1. **ENABLE WINDOWS DEFENDER**`n"
        }
        if ($SystemInfo.RAMUsagePercent -gt 70) {
            $aiReport += "2. **OPTIMIZE MEMORY USAGE**`n"
        }
        
        $aiReport += "`n"
        
        # For AI Assistant
        $aiReport += "## FOR AI ASSISTANT - ANALYSIS GUIDE`n"
        $aiReport += "When analyzing this report, consider:`n"
        $aiReport += "1. **Hardware vs Software**: Disk errors + high temps = likely hardware. WMI errors = likely software.`n"
        $aiReport += "2. **Temperature**: CPU >85°C causes throttling. Disk >60°C reduces lifespan.`n"
        $aiReport += "3. **RAM**: High usage with available RAM = software. High usage with low available = hardware limit.`n"
        $aiReport += "4. **Error Patterns**: Clustered errors = scheduled tasks. Random errors = hardware.`n"
        $aiReport += "`n"
        
        # Instructions
        $aiReport += "## HOW TO USE THIS REPORT`n"
        $aiReport += "1. Copy ALL text from this report`n"
        $aiReport += "2. Paste into AI assistant (ChatGPT, Gemini, Copilot, etc.)`n"
        $aiReport += "3. Ask questions like:`n"
        $aiReport += '   • "Based on this report, what are the top 3 issues?"`n'
        $aiReport += '   • "The report shows disk errors. Is my hardware failing?"`n'
        $aiReport += '   • "How do I fix the WMI errors mentioned?"`n'
        $aiReport += "`n"
        
        # Technical Notes
        $aiReport += "## TECHNICAL NOTES`n"
        $aiReport += "- Scan of $($LogInfo.Statistics.TotalLogs) Windows event logs`n"
        $aiReport += "- Hardware analysis (temps, RAM, SMART)`n"
        $aiReport += "- Ghost devices detection`n"
        $aiReport += "- Task frequency analysis`n"
        $aiReport += "- All data preserved, no system changes`n"
        $aiReport += "- Anonymized for privacy`n"
        $aiReport += "- Generated by EventLogDoctor v$ScriptVersion`n"
        $aiReport += "`n"
        
        $aiReport += "=" * 70 + "`n"
        $aiReport += "END OF REPORT`n"
        
        # Save reports
        $aiReportFile = "${OutputFolder}\Diagnostics_Report_${timestamp}.txt"
        $aiReport | Out-File $aiReportFile -Encoding UTF8
        $reports.AIReport = $aiReportFile
        
        $briefReport = "# QUICK SUMMARY`n"
        $briefReport += "Health Score: $healthScore/100`n"
        $briefReport += "Critical events: $($stats.Critical)`n"
        $briefReport += "Disk errors: $($EventAnalysis.Flags.DiskErrorCount)`n"
        $briefReport += "Ghost devices: $($GhostDevices.DisabledDevices)`n"
        $briefReport += "CPU Temp: $(if($Temperatures.CPU.Temperature -ne 'N/A'){"$($Temperatures.CPU.Temperature)°C"}else{"N/A"})`n"
        $briefReport += "RAM Usage: $($SystemInfo.RAMUsagePercent)%`n"
        
        $briefFile = "${OutputFolder}\Quick_Summary_${timestamp}.txt"
        $briefReport | Out-File $briefFile -Encoding UTF8
        $reports.BriefReport = $briefFile
        
        if ($isRussianOS) {
            Write-Info "Создано отчетов:"
            Write-Info "  • Детальный отчет: Diagnostics_Report_${timestamp}.txt"
            Write-Info "  • Краткий отчет: Quick_Summary_${timestamp}.txt"
            Write-Success "Отчеты созданы"
        } else {
            Write-Info "Reports created:"
            Write-Info "  • Detailed report: Diagnostics_Report_${timestamp}.txt"
            Write-Info "  • Brief report: Quick_Summary_${timestamp}.txt"
            Write-Success "Reports created successfully"
        }
        
    } catch {
        if ($isRussianOS) {
            Write-Error "Ошибка создания отчетов: $_"
        } else {
            Write-Error "Error creating reports: $_"
        }
    }
    
    return $reports
}

# ================= ОСНОВНАЯ ПРОГРАММА =================

Clear-Host
if ($isRussianOS) {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "    EVENTLOGDOCTOR v5.7 - ПРОВЕРКА СИСТЕМЫ" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Этот скрипт выполнит:" -ForegroundColor White
    Write-Host "• Сканирование журналов Windows" -ForegroundColor Yellow
    Write-Host "• Анализ железа (температуры, RAM, SMART)" -ForegroundColor Yellow
    Write-Host "• Проверку отключенных устройств" -ForegroundColor Yellow
    Write-Host "• Анализ частоты задач" -ForegroundColor Yellow
    Write-Host "• Проверку дисков" -ForegroundColor Yellow
    Write-Host "• Создание отчетов для ИИ" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Безопасный режим: ДАННЫЕ НЕ ИЗМЕНЯЮТСЯ" -ForegroundColor Green
    Write-Host "Принципы: Только чтение, сохранение приватности" -ForegroundColor Green
    Write-Host ""
    Write-Host "Начать проверку? (Y/N)" -ForegroundColor White
} else {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "    EVENTLOGDOCTOR v5.7 - SYSTEM CHECK" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script will perform:" -ForegroundColor White
    Write-Host "• Windows event logs scan" -ForegroundColor Yellow
    Write-Host "• Hardware analysis (temps, RAM, SMART)" -ForegroundColor Yellow
    Write-Host "• Disabled devices check" -ForegroundColor Yellow
    Write-Host "• Task frequency analysis" -ForegroundColor Yellow
    Write-Host "• Disk check" -ForegroundColor Yellow
    Write-Host "• Creation of AI reports" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Safe mode: NO DATA CHANGES" -ForegroundColor Green
    Write-Host "Principles: Read-only, privacy-preserving" -ForegroundColor Green
    Write-Host ""
    Write-Host "Start check? (Y/N)" -ForegroundColor White
}

$confirm = Read-Host
if ($confirm -notmatch "^[YyДд]") {
    if ($isRussianOS) {
        Write-Host "Отмена..." -ForegroundColor Gray
    } else {
        Write-Host "Cancelled..." -ForegroundColor Gray
    }
    Start-Sleep -Seconds 1
    exit
}

Write-Host ""
if ($isRussianOS) {
    Write-Host "Запуск проверки..." -ForegroundColor Cyan
} else {
    Write-Host "Starting check..." -ForegroundColor Cyan
}
Start-Sleep -Seconds 2

# Сбор данных
Clear-Host
if ($isRussianOS) {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "    ВЫПОЛНЕНИЕ ПРОВЕРКИ" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "    EXECUTING CHECK" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
}

# 1. System Information
$systemInfo = Get-SystemInformation

# 2. Temperature Check
$temperatures = Check-Temperatures

# 3. Disk Health Check
$diskHealth = Check-DiskHealth

# 4. Log Discovery
$logInfo = Discover-EventLogs -Days $DaysToAnalyze

# 5. Event Collection
$allEvents = Collect-AllEvents -Days $DaysToAnalyze -LogGroups $logInfo

# 6. Event Analysis
$eventAnalysis = Analyze-Events -Events $allEvents

# 7. Ghost Devices Check
$ghostDevices = Check-GhostDevices

# 8. Services Check
$services = Check-Services

# 9. Disks Check
$disks = Check-Disks

# 10. Hidden Tasks Check
$hiddenTasks = Check-HiddenTasks

# 11. Security Check
$security = Check-Security

# 12. Report Creation
$reports = Create-Reports -SystemInfo $systemInfo -EventAnalysis $eventAnalysis `
                         -LogInfo $logInfo -Services $services -Disks $disks `
                         -DiskHealth $diskHealth -Temperatures $temperatures `
                         -HiddenTasks $hiddenTasks -Security $security `
                         -GhostDevices $ghostDevices -Days $DaysToAnalyze

# Финальный экран
Clear-Host
if ($isRussianOS) {
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host "    ПРОВЕРКА ЗАВЕРШЕНА!" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host "    CHECK COMPLETED!" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
}

# Результаты
if ($isRussianOS) {
    Write-Host "📊 РЕЗУЛЬТАТЫ:" -ForegroundColor Cyan
    Write-Host "├─ Компьютер: $($systemInfo.ComputerName)" -ForegroundColor White
    Write-Host "├─ ОЗУ: $($systemInfo.UsedRAM_GB)/$($systemInfo.TotalRAM_GB) ГБ ($($systemInfo.RAMUsagePercent)%)" -ForegroundColor White
    Write-Host "├─ Температура CPU: $(if($temperatures.CPU.Temperature -ne 'N/A'){"$($temperatures.CPU.Temperature)°C"}else{"N/A"})" -ForegroundColor $(if($temperatures.CPU.Temperature -ne 'N/A' -and $temperatures.CPU.Temperature -gt 75){"Red"}else{"Gray"})
    Write-Host "├─ Журналов: $($logInfo.Statistics.TotalLogs)" -ForegroundColor White
    Write-Host "├─ Событий: $($eventAnalysis.Statistics.Total)" -ForegroundColor White
    Write-Host "├─ Критических: $($eventAnalysis.Statistics.Critical)" -ForegroundColor $(if($eventAnalysis.Statistics.Critical -gt 0){"Red"}else{"Gray"})
    Write-Host "├─ Отключенных устройств: $($ghostDevices.DisabledDevices)" -ForegroundColor $(if($ghostDevices.DisabledDevices -gt 20){"Yellow"}else{"Gray"})
    Write-Host "├─ Ошибок дисков: $($eventAnalysis.Flags.DiskErrorCount)" -ForegroundColor $(if($eventAnalysis.Flags.DiskErrorCount -gt 0){"Yellow"}else{"Gray"})
    Write-Host "├─ Скрытых задач: $($hiddenTasks.Statistics.HiddenTasks)" -ForegroundColor $(if($hiddenTasks.Statistics.HiddenTasks -gt 0){"Yellow"}else{"Gray"})
    Write-Host "└─ Частых задач: $($hiddenTasks.TopFrequentTasks.Count)" -ForegroundColor $(if($hiddenTasks.TopFrequentTasks.Count -gt 0){"Yellow"}else{"Gray"})
    Write-Host ""
} else {
    Write-Host "📊 RESULTS:" -ForegroundColor Cyan
    Write-Host "├─ Computer: $($systemInfo.ComputerName)" -ForegroundColor White
    Write-Host "├─ RAM: $($systemInfo.UsedRAM_GB)/$($systemInfo.TotalRAM_GB) GB ($($systemInfo.RAMUsagePercent)%)" -ForegroundColor White
    Write-Host "├─ CPU Temp: $(if($temperatures.CPU.Temperature -ne 'N/A'){"$($temperatures.CPU.Temperature)°C"}else{"N/A"})" -ForegroundColor $(if($temperatures.CPU.Temperature -ne 'N/A' -and $temperatures.CPU.Temperature -gt 75){"Red"}else{"Gray"})
    Write-Host "├─ Logs: $($logInfo.Statistics.TotalLogs)" -ForegroundColor White
    Write-Host "├─ Events: $($eventAnalysis.Statistics.Total)" -ForegroundColor White
    Write-Host "├─ Critical: $($eventAnalysis.Statistics.Critical)" -ForegroundColor $(if($eventAnalysis.Statistics.Critical -gt 0){"Red"}else{"Gray"})
    Write-Host "├─ Disabled devices: $($ghostDevices.DisabledDevices)" -ForegroundColor $(if($ghostDevices.DisabledDevices -gt 20){"Yellow"}else{"Gray"})
    Write-Host "├─ Disk errors: $($eventAnalysis.Flags.DiskErrorCount)" -ForegroundColor $(if($eventAnalysis.Flags.DiskErrorCount -gt 0){"Yellow"}else{"Gray"})
    Write-Host "├─ Hidden tasks: $($hiddenTasks.Statistics.HiddenTasks)" -ForegroundColor $(if($hiddenTasks.Statistics.HiddenTasks -gt 0){"Yellow"}else{"Gray"})
    Write-Host "└─ Frequent tasks: $($hiddenTasks.TopFrequentTasks.Count)" -ForegroundColor $(if($hiddenTasks.TopFrequentTasks.Count -gt 0){"Yellow"}else{"Gray"})
    Write-Host ""
}

# Файлы
if ($isRussianOS) {
    Write-Host "📁 СОЗДАННЫЕ ОТЧЕТЫ:" -ForegroundColor Cyan
    Write-Host "├─ 1. Детальный отчет для ИИ:" -ForegroundColor Green
    Write-Host "│  └─ Diagnostics_Report_*.txt" -ForegroundColor White
    Write-Host "├─ 2. Краткий отчет:" -ForegroundColor Yellow
    Write-Host "│  └─ Quick_Summary_*.txt" -ForegroundColor White
    Write-Host "└─ 3. Все файлы в папке:" -ForegroundColor Blue
    Write-Host "   └─ $OutputFolder" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "📁 CREATED REPORTS:" -ForegroundColor Cyan
    Write-Host "├─ 1. Detailed report for AI:" -ForegroundColor Green
    Write-Host "│  └─ Diagnostics_Report_*.txt" -ForegroundColor White
    Write-Host "├─ 2. Brief report:" -ForegroundColor Yellow
    Write-Host "│  └─ Quick_Summary_*.txt" -ForegroundColor White
    Write-Host "└─ 3. All files in folder:" -ForegroundColor Blue
    Write-Host "   └─ $OutputFolder" -ForegroundColor White
    Write-Host ""
}

# Инструкции для ИИ
if ($isRussianOS) {
    Write-Host "🤖 ИНСТРУКЦИИ ДЛЯ ИИ:" -ForegroundColor Magenta
    Write-Host "1. Откройте папку: $OutputFolder" -ForegroundColor White
    Write-Host "2. Найдите файл Diagnostics_Report_*.txt и откройте его" -ForegroundColor White
    Write-Host "3. Скопируйте ВЕСЬ текст из файла (Ctrl+A, Ctrl+C)" -ForegroundColor White
    Write-Host "4. Вставьте в чат с ИИ (ChatGPT, Gemini, Copilot и т.д.)" -ForegroundColor White
    Write-Host "5. Спросите (можно скопировать):" -ForegroundColor White
    Write-Host '   • "Какие 3 главные проблемы в отчете?"' -ForegroundColor Cyan
    Write-Host '   • "Ошибки дисков - это аппаратная проблема?"' -ForegroundColor Cyan
    Write-Host '   • "Как исправить WMI ошибки?"' -ForegroundColor Cyan
    Write-Host '   • "Частые задачи - это нормально?"' -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📝 Отчет содержит анализ железа и софта" -ForegroundColor Green
    Write-Host "   ИИ даст рекомендации для новичков" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "🤖 INSTRUCTIONS FOR AI:" -ForegroundColor Magenta
    Write-Host "1. Open folder: $OutputFolder" -ForegroundColor White
    Write-Host "2. Find file Diagnostics_Report_*.txt and open it" -ForegroundColor White
    Write-Host "3. Copy ALL text from the file (Ctrl+A, Ctrl+C)" -ForegroundColor White
    Write-Host "4. Paste into AI chat (ChatGPT, Gemini, Copilot, etc.)" -ForegroundColor White
    Write-Host "5. Ask questions like:" -ForegroundColor White
    Write-Host '   • "What are the top 3 issues in this report?"' -ForegroundColor Cyan
    Write-Host '   • "Are the disk errors hardware problems?"' -ForegroundColor Cyan
    Write-Host '   • "How to fix WMI errors?"' -ForegroundColor Cyan
    Write-Host '   • "Are frequent tasks normal?"' -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📝 Report includes hardware and software analysis" -ForegroundColor Green
    Write-Host "   AI will provide beginner-friendly recommendations" -ForegroundColor Gray
    Write-Host ""
}

# Меню
if ($isRussianOS) {
    Write-Host "🎯 ВЫБЕРИТЕ ДЕЙСТВИЕ:" -ForegroundColor Cyan
    Write-Host "  1. 📂 Открыть папку с отчетами" -ForegroundColor Green
    Write-Host "  2. 🔄 Запустить проверку еще раз" -ForegroundColor Yellow
    Write-Host "  3. ❌ Выйти" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "🎯 SELECT ACTION:" -ForegroundColor Cyan
    Write-Host "  1. 📂 Open reports folder" -ForegroundColor Green
    Write-Host "  2. 🔄 Run check again" -ForegroundColor Yellow
    Write-Host "  3. ❌ Exit" -ForegroundColor Gray
    Write-Host ""
}

# Простое меню
while ($true) {
    if ($isRussianOS) {
        $action = Read-Host "Ваш выбор (1-3)"
    } else {
        $action = Read-Host "Your choice (1-3)"
    }
    
    switch ($action) {
        "1" {
            if (Test-Path $OutputFolder) {
                explorer $OutputFolder
                Write-Host ""
                if ($isRussianOS) {
                    Write-Host "Папка открыта!" -ForegroundColor Green
                    Write-Host "Нажмите Enter для выхода..." -ForegroundColor Gray
                } else {
                    Write-Host "Folder opened!" -ForegroundColor Green
                    Write-Host "Press Enter to exit..." -ForegroundColor Gray
                }
                Read-Host
            }
            exit
        }
        "2" {
            if ($isRussianOS) {
                Write-Host "Перезапуск проверки..." -ForegroundColor Yellow
            } else {
                Write-Host "Restarting check..." -ForegroundColor Yellow
            }
            Start-Sleep -Seconds 2
            & $MyInvocation.MyCommand.Path
            exit
        }
        "3" {
            if ($isRussianOS) {
                Write-Host "Выход..." -ForegroundColor Gray
            } else {
                Write-Host "Exiting..." -ForegroundColor Gray
            }
            Start-Sleep -Seconds 1
            exit
        }
        default {
            if ($isRussianOS) {
                Write-Host "Неверный выбор. Введите 1, 2 или 3." -ForegroundColor Red
            } else {
                Write-Host "Invalid choice. Enter 1, 2 or 3." -ForegroundColor Red
            }
        }
    }
}
