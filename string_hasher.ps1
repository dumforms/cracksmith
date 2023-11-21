# Set default values
$DEFAULT_FLAG = "default"
$DEFAULT_LIST_PATH = "./10k-most-common.txt"
$DEFAULT_HASH_ALGORITHM = "MD5"

# Functions
function Script:Write-Host_Plus {
    param (
        [String]$msg_type,
        [String]$message
    )
    switch ($msg_type) {
        "error" {Write-Host "ERROR : " -ForegroundColor Red -NoNewline; break}
        "status" {Write-Host "STATUS: " -ForegroundColor Green -NoNewline; break}
    }
    Write-Host $message
}
# Validate input filepath
$valid_input = $false
while (!$valid_input) {
    $list_path = Read-Host "INPUT : File containing passwords to hash"
    # Check for default input
    if (($list_path -eq $DEFAULT_FLAG) -or ($list_path -eq "")) {
        $list_path = $DEFAULT_LIST_PATH
    }
    # If only a name is provided, assume the local directory
    if (!($list_path.Contains("/") -or $list_path.Contains("\"))) {
        $list_path = "./" + $list_path
    }

    # Attempt to read the file, throw error if the file can't be reached
    try {
        $input_list = Get-Content $list_path -ErrorAction Stop
        $valid_input = $true
    } catch {
        Write-Host_Plus -msg_type error -message "Invalid path! Did you specify the full path?"
    }
}

# Validate hash algorithm
$valid_input = $false
while (!$valid_input) {
    $hash_algorithm = Read-Host "INPUT : Specify a hash algorithm"
    # Check for default input
    if (($hash_algorithm -eq $DEFAULT_FLAG) -or ($hash_algorithm -eq "")) {
        $hash_algorithm = $DEFAULT_HASH_ALGORITHM
    }
    # Assert that submitted hash type matches a valid format
    switch ($hash_algorithm.ToUpper()) {
        "SHA1" {$valid_input = $true; break}
        "SHA256" {$valid_input = $true; break}
        "SHA384" {$valid_input = $true; break}
        "SHA512" {$valid_input = $true; break}
        "MACTRIPLEDES" {$hash_algorithm = "MACTripleDES"; $valid_input = $true; break}
        "MD5" {$valid_input = $true; break}
        "RIPEMD160" {$valid_input = $true; break}
        default {Write-Host_Plus -msg_type error -message "Unrecognized algorithm!"; break}
    }
    if ($valid_input) {
        Write-Host_Plus -msg_type status -message "Algorithm set to $hash_algorithm"
    }
}

# Try to write the output file, otherwise add a line break to the existing file
$time = Get-Date -Format "yyyyMMddHHmmss"
$output_path = "./hashes_$($hash_algorithm)_$time.txt"
try {
	[void](New-Item -Itemtype File -Path $output_path -ErrorAction Stop)
}
catch [System.IO.IOException] {
	Add-Content -Path $output_path -Value "`n"
}

# Write the hash of each line in $list_path to the output file
Write-Host_Plus -msg_type status -message "Generating Hashes from `'$list_path`' and saving to `'$output_path`'..."
$line_count = 0
foreach ($line in $input_list) {
    $line_count ++
    try {
        $stringAsStream = [IO.MemoryStream]::new([byte[]][char[]]$line)
        $hash = Get-FileHash -InputStream $stringAsStream -Algorithm $hash_algorithm | ForEach-Object -MemberName Hash
        $stringAsStream.Dispose()
        Add-Content -Path $output_path -Value "$hash"
    } catch [System.Management.Automation.PSInvalidCastException] {
        Write-Host_Plus -msg_type error -message "Could not convert $line to $hash_algorithm hash. Skipping..."
    }
    switch ($line_count) {
        {[Math]::Abs($_ - (($input_list.Length)/10)) -lt 1} {Write-Host_Plus -msg_type status -message "10% complete"}
        {[Math]::Abs($_ - (($input_list.Length)/5)) -lt 1} {Write-Host_Plus -msg_type status -message "20% complete"}
        {[Math]::Abs($_ - (($input_list.Length*3)/10)) -lt 1} {Write-Host_Plus -msg_type status -message "30% complete"}
        {[Math]::Abs($_ - (($input_list.Length*2)/5)) -lt 1} {Write-Host_Plus -msg_type status -message "40% complete"}
        {[Math]::Abs($_ - (($input_list.Length)/2)) -lt 1} {Write-Host_Plus -msg_type status -message "50% complete"}
        {[Math]::Abs($_ - (($input_list.Length*3)/5)) -lt 1} {Write-Host_Plus -msg_type status -message "60% complete"}
        {[Math]::Abs($_ - (($input_list.Length*7)/10)) -lt 1} {Write-Host_Plus -msg_type status -message "70% complete"}
        {[Math]::Abs($_ - (($input_list.Length*4)/5)) -lt 1} {Write-Host_Plus -msg_type status -message "80% complete"}
        {[Math]::Abs($_ - (($input_list.Length*9)/10)) -lt 1} {Write-Host_Plus -msg_type status -message "90% complete"}
    }
}

Read-Host "Script complete. Press ENTER to exit"