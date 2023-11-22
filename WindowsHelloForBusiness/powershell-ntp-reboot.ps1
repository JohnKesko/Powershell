$logFile = "C:\temp\NTP-Reboot.txt"
$ntpServer = "myntpserver.domain.com"
$rebootTime = Get-Date
$w32tmOutput = w32tm /stripchart /computer:$ntpServer /dataonly /samples:5 2>&1

$logEntry = "Computer rebooted at $rebootTime`r`nW32TM Output:`r`n$w32tmOutput"
Add-Content -path $logFile -Value $logEntry