# TODO:
#  - add rainbow table attacks

## CONSTANTS AND DEFAULT SETTINGS##
# General defaults
Set-Variable -name DefaultFlag -option Constant -value ([string]"")
Set-Variable -name AttackTypes -option Constant -value ([string](
    "a) Brute Force" + "`n" +
    "b) Rainbow Table" + "`n" +
    "c) Dictionary"
))
Set-Variable -name DefaultAttackType -option Constant -value ([string]"a")
Set-Variable -name DefaultVictimPath -option Constant -value ([string]"$PSScriptRoot\victim.txt")
Set-Variable -name DefaultHashAlgorithm -option Constant -value ([string]"MD5")
Set-Variable -name SupressUnhelpfulErrors -option Constant -value ([bool]$true)

# Script-level variable declarations
$Script:TotalPasswordsCracked = 0

# Brute force constants
Set-Variable -name CharacterSets -option Constant -value ([string](
    "a) Numbers             e) All letters" + "`n" +
    "b) Lowercase letters   f) All alphanumeric" + "`n" +
    "c) Uppercase letters   g) Most characters (reduced symbols)" + "`n" +
    "d) Symbols             h) All characters"
))
Set-Variable -name CharsetNumbers -option Constant -value (
    [string]"0123456789"
)
Set-Variable -name CharsetLowercase -option Constant -value (
    [string]"abcdefghijklmnopqrstuvwxyz"
)
Set-Variable -name CharsetUppercase -option Constant -value (
    [string]($CharsetLowercase.ToUpper())
)
Set-Variable -name CharsetSymbols -option Constant -value (
    [string]"!@#$%^&*(),./?;:[]{}-+_=\|<>~```"`'"
)
Set-Variable -name CharsetAllLetters -option Constant -value (
    [string]($CharsetLowercase + $CharsetUppercase)
)
Set-Variable -name CharsetAllAlphanumeric -option Constant -value (
    [string]($CharsetAllLetters + $CharsetNumbers)
)
Set-Variable -name CharsetReducedSymbols -option Constant -value (
    [string]($CharsetAllAlphanumeric + "!&*.?;-+\`'")
)
Set-Variable -name CharsetAll -option Constant -value (
    [string]($CharsetAllAlphanumeric + $CharsetSymbols)
)

# Brute force defaults
Set-Variable -name DefaultCharacterSet -option Constant -value ([string]$CharsetNumbers)
Set-Variable -name DefaultMinimumLength -option Constant -value ([int]4)
Set-Variable -name DefaultMaximumLength -option Constant -value ([int]8)

# Rainbow table constants
# Rainbow table defaults

# Dictionary attack defaults
Set-Variable -name DefaultDictionaryDirectory -option Constant -value (
    [string]"$PSScriptRoot\Dictionaries"
)
Set-Variable -name DefaultDictionaryPath -option Constant -value (
    [string]"$DefaultDictionaryDirectory\100k-most-used-passwords-NCSC.txt"
)
## END CONSTANTS ##

## FUNCTIONS ##
function Write-HostStatusMsg {
<#
.SYNOPSIS
    Adds colored flag text to the beginning of console messages

.DESCRIPTION
    Write-HostStatusMsg is a funciton that displays a flag (such as ERROR or STATUS) in an associated color
    before printing the rest of the console output using the default Write-Host function.

.PARAMETER Type
    The name of the flag to set

.PARAMETER Message
    The string to print as plain text after the flag

.EXAMPLE
    Write-HostStatusMsg -Type status -Message "This is an example status message!"

.OUTPUTS
    None (writes to the console using Write-Host)

.NOTES
    Author: Matthew Dumford
    Email: dumforms@mail.uc.edu
#>
    param (
        [Parameter(Mandatory)]
        [String]$Type,
        [Parameter(Mandatory)]
        [String]$Message
    )
    switch ($Type) {
        "error" {Write-Host "ERROR : " -ForegroundColor Red -NoNewline; break}
        "status" {Write-Host "STATUS: " -ForegroundColor Green -NoNewline; break}
        "crack" {Write-Host "CRACK : " -ForegroundColor Yellow -NoNewline; break}
        "update" {Write-Host "UPDATE: " -ForegroundColor Cyan -NoNewline; break}
    }
    Write-Host $Message
}


function Compare-Hashes {
<#
.SYNOPSIS
    Checks a known hash string against an array of other hashes.

.DESCRIPTION
    Compare-Hashes is a function that checks a specific hash string against an array of other
    hash strings. If a match is found, perform the following steps:
     - Remove the matched hash string from the array of hash strings
     - Increment the number of passwords cracked
     - Write the matched hash string and its plaintext to the console
     - Write the matched hash string and its plaintext to the specified output file.
    After every 100th match (aka when the number of total passwords cracked is
    divisible by 100) write a message to the console.

.PARAMETER Plaintext
    The known plaintext of the hash string being compared to the array.

.PARAMETER Hash
    The hash string being compared to the array.

.PARAMETER OutputFilePath
    The filepath to which the output should be written.

.EXAMPLE
    Compare-Hashes -Plaintext "password" -Hash "ANMD5HASHMIGHTGOHERE" -OutputFilePath ".\output.txt"

.OUTPUTS
    None (Writes to console and file if match is found, otherwise returns with no output)

.NOTES
    Relies on the script-level variable $VictimFileContents, which should be an array of hash strings
    that includes all yet-unmatched strings from the original input file.

    Author: Matthew Dumford
    Email: dumforms@mail.uc.edu
#> 
    param (
        [Parameter(Mandatory)]
        [String]$Plaintext,
        [Parameter(Mandatory)]
        [String]$Hash,
        [Parameter(Mandatory)]
        [String]$OutputFilePath
    )

    foreach ($Line in $script:VictimFileContents) {
        if ($Hash -eq $Line) {
            $script:VictimFileContents = $script:VictimFileContents | Where-Object {$_ -notmatch $Hash}
            $script:TotalPasswordsCracked ++
            if ($Plaintext.Length -lt 8) {
                Write-HostStatusMsg -Type crack -Message "$Plaintext`t`t| $Hash"
                Add-Content -Path $OutputFilePath -Value "$Plaintext`t`t| $Hash"
            } else {    # $Plaintext.Length greater than or equal to 8
                Write-HostStatusMsg -Type crack -Message "$Plaintext`t| $Hash"
                Add-Content -Path $OutputFilePath -Value "$Plaintext`t| $Hash"
            }
            if ($script:TotalPasswordsCracked % 100 -eq 0) {
                Write-HostStatusMsg -Type update -Message "$script:TotalPasswordsCracked total passwords cracked!"
            }
            return
        }
    }
}


function Get-HashedValue {
<#
.SYNOPSIS
    Compute the hash value of a string

.DESCRIPTION
    Use a hashing algorithm to hash a given input string and return the hashed value.
    Converts the string to a stream object and passes it to Get-FileHash

.PARAMETER Plaintext
    The input string to be hashed

.PARAMETER HashType
    The hashing algorithm to use

.EXAMPLE
    Get-HashedValue -Plaintext "password" -HashType "MD5"

.OUTPUTS
    String

.NOTES
    The range of supported hashing algorithms are dependant on the Get-FileHash function.

    Author: Matthew Dumford
    Email: dumforms@mail.uc.edu
#>
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [String]$Plaintext,
        [String]$HashType = $Script:DefaultHashAlgorithm
    )

    try {
        $stringAsStream = [IO.MemoryStream]::new([byte[]][char[]]$Plaintext)
        $params = @{
            "InputStream" = $stringAsStream
            "Algorithm" = $HashType
            "ErrorAction" = "Stop"
        }
        $Hash = Get-FileHash @params | ForEach-Object -MemberName Hash
        $stringAsStream.Dispose()
    } catch {
        if ($SupressUnhelpfulErrors -eq $false) {
            Write-HostStatusMsg -Type error -Message "Could not convert $Plaintext to $HashType hash. Skipping..."
        }
        $Hash = ""
    }
    return $Hash
}


function New-BruteForceAttack {
<#
.SYNOPSIS
    Recursively brute-force password hashes

.DESCRIPTION
    Recursively brute-force every password permutation possible, given a character set
    and a maximum length range. Starting (i.e., minimum) length is set by the loop that
    calls this function.

.PARAMETER CharacterSet
    The set of characters available to guess with, as a string (function converts it to a CharArray)

.PARAMETER HashType
    The hashing algorithm to use on each plaintext permutation. Passed to Get-HashedValue

.PARAMETER OutputFilePath
    The filepath to write results to. Passed to Compare-Hashes

.PARAMETER Length
    The maximum password length to guess

.PARAMETER Plaintext
    The current guess string. Allows the function to recursively pass data to itself.
    Defaults to an empty string if not specified.

.EXAMPLE
    $params = @{
        "CharacterSet" = "abcdefg123"
        "HashType" = "MD5"
        "OutputFilePath" = ".\output.txt"
        "Length" = "8"
    }
    New-BruteForceAttack @params

.INPUTS
    Hashtable of string parameters

.OUTPUTS
    None (calls Compare-Hashes to write output to files and console)

.NOTES
    Author: Matthew Dumford
    Email: dumforms@mail.uc.edu
#>
    param (
        [String]$CharacterSet = $DefaultCharacterSet,
        [String]$HashType = $DefaultHashAlgorithm,
        [Parameter(Mandatory)]
        [String]$OutputFilePath,
        [Parameter(Mandatory)]
        [Int]$Length,
        [String]$Plaintext = ""
    )
    $HashedGuess = Get-HashedValue -Plaintext $Plaintext -HashType $HashType

    if ($Length -eq 0) {
        $Params = @{
            "Plaintext" = $Plaintext
            "Hash" = $HashedGuess
            "OutputFilePath" = $OutputFilePath
        }
        Compare-Hashes @Params
    } else {
        foreach ($Char in $CharacterSet.ToCharArray()) {
            $NewPlaintext = $Plaintext + $Char
            $NewParams = @{
                "CharacterSet" = $CharacterSet
                "HashType" = $HashType
                "OutputFilePath" = $OutputFilePath
                "Length" = $($Length - 1)
                "Plaintext" = $NewPlaintext
            }
            New-BruteForceAttack @NewParams
        }
    }
}
## END FUNCTIONS ##


## MAIN PROGRAM ##
Write-Host $AsciiBanner
# Validate attack type.
# - If the default flag is provided, use the default attack type.
# - Otherwise, match the input to one of the valid types.
$ValidInput = $false
while (!$ValidInput) {
    Write-Host $AttackTypes
    $AttackType = Read-Host "INPUT : Select one of the above attack types (a-c)"
    if ($AttackType -eq $DefaultFlag) {
        $AttackType = $DefaultAttackType
        $ValidInput = $true
        Write-HostStatusMsg -Type status -Message "Defaulting to option ($AttackType)"
    } else {
        switch ($AttackType.ToLower()) {
            "a" {$ValidInput = $true; break}
            "b" {$ValidInput = $true; break}
            "c" {$ValidInput = $true; break}
            default {Write-HostStatusMsg -Type error -Message "Invalid attack type selected."}
        }
    }
}

# Get victim filepath.
# - If the default flag is provided, use the default path.
# - If a root path is not provided, assume the local directory.
# - If an extension is not provided, assume a .txt extension.
# - Verify that the file can be read before leaving the input loop
$ValidInput = $false
while (!$ValidInput) {
    $VictimFilepath = Read-Host "INPUT : Name the victim file containing hashes to attack"
    if ($VictimFilepath -eq $DefaultFlag) {
        $VictimFilepath = $DefaultVictimPath
        Write-HostStatusMsg -Type status -Message "Defaulting to $VictimFilepath"
        try {
            $VictimFileContents = Get-Content -Path $VictimFilepath -ErrorAction Stop
            $ValidInput = $true
        } catch {
            Write-HostStatusMsg -Type error -Message "Cannot find default victim file."
        }
    } else {
        if (!($VictimFilepath.Contains("/") -or $VictimFilepath.Contains("\"))) {
            $VictimFilepath = ".\" + $VictimFilepath
        }
        if ($VictimFilepath -notmatch ".*?\.(\w{2,4})?$") {
            $VictimFilepath += ".txt"
        }

        try {
            $VictimFileContents = Get-Content -Path $VictimFilepath -ErrorAction Stop
            $ValidInput = $true
        } catch {
            Write-HostStatusMsg -Type error -Message "Invalid path. Did you specify the full path?"
        }
    }
}

# Get victim file length (i.e., number of rows) from the contents
$VictimFileLength = $VictimFileContents.Length

# Get hashing algorithm used on victim file (i.e., the algorithm to use during attack).
# - If the default flag is provided, assume the default hash algorithm.
# - Otherwise, match the input to one of the valid types.
$ValidInput = $false
while (!$ValidInput) {
    $HashAlgorithm = Read-Host "INPUT : Name the hash algorithm to use for the attack"
    if ($HashAlgorithm -eq $DefaultFlag) {
        $HashAlgorithm = $DefaultHashAlgorithm
        $ValidInput = $true
        Write-HostStatusMsg -Type status -Message "Defaulting to $HashAlgorithm"
    } else {
        switch ($HashAlgorithm.ToUpper()) {
            "SHA1" {$ValidInput = $true; break}
            "SHA256" {$ValidInput = $true; break}
            "SHA384" {$ValidInput = $true; break}
            "SHA512" {$ValidInput = $true; break}
            "MACTRIPLEDES" {$HashAlgorithm = "MACTripleDES"; $ValidInput = $true; break}
            "MD5" {$ValidInput = $true; break}
            "RIPEMD160" {$ValidInput = $true; break}
            default {Write-HostStatusMsg -Type error -Message "Unrecognized hash algorithm."; break}
        }
    }
}

# Validate additional parameters based on attack type
switch ($AttackType) {
    "a" { ## Brute Force Attack ##
        # Get charset to use.
        # - If the default flag is provided, assume the default character set.
        # - Otherwise, match the input to one of the valid types.
        $ValidInput = $false
        while (!$ValidInput) {
            Write-Host $CharacterSets
            $CharacterSet = Read-Host "INPUT : Select one of the above character sets (a-h)"
            if ($CharacterSet -eq $DefaultFlag) {
                $CharacterSet = $DefaultCharacterSet
                $ValidInput = $true
                $Message = "Defaulting to the following character set: `'$CharacterSet`'"
                Write-HostStatusMsg -Type status -Message $Message
            } else {
                switch ($CharacterSet.ToLower()) {
                    "a" {$CharacterSet = $CharsetNumbers; $ValidInput = $true; break}
                    "b" {$CharacterSet = $CharsetLowercase; $ValidInput = $true; break}
                    "c" {$CharacterSet = $CharsetUppercase; $ValidInput = $true; break}
                    "d" {$CharacterSet = $CharsetSymbols; $ValidInput = $true; break}
                    "e" {$CharacterSet = $CharsetAllLetters; $ValidInput = $true; break}
                    "f" {$CharacterSet = $CharsetAllAlphanumeric; $ValidInput = $true; break}
                    "g" {$CharacterSet = $CharsetReducedSymbols; $ValidInput = $true; break}
                    "h" {$CharacterSet = $CharsetAll; $ValidInput = $true; break}
                    default {Write-HostStatusMsg -Type error -Message "Invalid character set option."}
                }
            }
        }

        # Get length range
        # - If the default flag is provided, assume the default minimum length.
        # - Verify that the input is an integer before leaving the loop.
        # - For the maximum value, verify that it is larger than the minimum value.
        $ValidInput = $false
        while (!$ValidInput) {
            $MinLength = Read-Host "INPUT : Set the minimum expected password length"
            if ($MinLength -eq $DefaultFlag) {
                $MinLength = $DefaultMinimumLength
                $ValidInput = $true
                Write-HostStatusMsg -Type status -Message "Defaulting to $MinLength"
            } else {
                try {
                    $MinLength = [int]$MinLength
                    if ($MinLength -ge 0) {
                        $ValidInput = $true
                    } else {
                        Write-HostStatusMsg -Type error -Message "Mimimum length must be at least zero."
                    }                    
                } catch [System.Management.Automation.PSInvalidCastException] {
                    Write-HostStatusMsg -Type error -Message "Minimum length must be a whole number."
                }
            }
        }

        $ValidInput = $false
        while (!$ValidInput) {
            $MaxLength = Read-Host "INPUT : Set the maximum expected password length"
            if ($MaxLength -eq $DefaultFlag) {
                $MaxLength = $DefaultMaximumLength
                $ValidInput = $true
                Write-HostStatusMsg -Type status -Message "Defaulting to $MaxLength"
            } else {
                try {
                    $MaxLength = [int]$MaxLength
                    if ($MaxLength -ge $MinLength) {
                        $ValidInput = $true
                    } else {
                        $Message = "Maximum length must be larger than minimum length."
                        Write-HostStatusMsg -Type error -Message $Message
                    }
                } catch [System.Management.Automation.PSInvalidCastException] {
                    Write-HostStatusMsg -Type error -Message "Maximum length must be a whole number."
                }
            }
        }

        # Set ouptut file name
        $Time = Get-Date -Format "yyyyMMddHHmmss"
        $OutputFilePath = "./cracked_bruteforce_$Time.txt"
        [void](New-Item -Itemtype File -Path $OutputFilePath)

        # Perform brute force attack
        $Feedback = "Starting brute force attack with the following parameters:`n"
        $Feedback += "Victim File    : $VictimFilepath`n"
        $Feedback += "Hash Algorithm : $HashAlgorithm`n"
        $Feedback += "Character Set  : $CharacterSet`n"
        $Feedback += "Length Range   : $MinLength - $MaxLength`n"
        $Feedback += "Results File   : $OutputFilePath"
        Write-HostStatusMsg -Type status -Message $Feedback

        $Time = Get-Date
        for ($CurrentLength = $MinLength; $CurrentLength -le $MaxLength; $CurrentLength ++) {
            if ($Script:TotalPasswordsCracked -eq $VictimFileContents.Length) {
                Write-HostStatusMsg -Type status -Message "All hashes in $VictimFilepath cracked!"
                Write-HostStatusMsg -Type status -Message "Results saved to $OutputFilePath"
                break
            }
            Write-HostStatusMsg -Type status -Message "Testing passwords of length $CurrentLength..."
            $params = @{
                "CharacterSet" = $CharacterSet
                "HashType" = $HashAlgorithm
                "OutputFilePath" = $OutputFilePath
                "Length" = $CurrentLength
            }
            New-BruteForceAttack @params
        }
    }
    "b" { ## Rainbow Table Attack ##
        # Get filepath to rainbow table
        
        # Set output file name
        $Time = Get-Date -Format "yyyyMMddHHmmss"
        $OutputFilePath = "$PSScriptRoot\cracked_rainbow_$Time.txt"
        [void](New-Item -Itemtype File -Path $OutputFilePath)
    }
    "c" { ## Dictionary Attack ##
        # Get filepath to dictionary wordlist.
        # - If the default flag is provided, use the default path.
        # - If a root path is not provided, assume the local .\Dictionaries directory.
        # - If an extension is not provided, assume a .txt extension.
        # - Verify that the file can be read before leaving the input loop
        $ValidInput = $false
        while (!$ValidInput) {
            $DictionaryFilepath = Read-Host "INPUT : Provide a path to the dictionary file to use"
            if ($DictionaryFilepath -eq $DefaultFlag) {
                $DictionaryFilepath = $DefaultDictionaryPath
                Write-HostStatusMsg -Type status -Message "Defaulting to $DictionaryFilepath"
                try {
                    $Dictionary = Get-Content -Path $DictionaryFilepath -ErrorAction Stop
                    $ValidInput = $true
                } catch {
                    Write-HostStatusMsg -Type error -Message "Cannot find default dictionary file."
                }
            } else {
                if (!($DictionaryFilepath.Contains("/") -or $DictionaryFilepath.Contains("\"))) {
                    $DictionaryFilepath = $DefaultDictionaryDirectory + "\" + $DictionaryFilepath
                }
                if ($DictionaryFilepath -notmatch ".*?\.(\w{2,4})?$") {
                    $DictionaryFilepath += ".txt"
                }

                try {
                    $Dictionary = Get-Content -Path $DictionaryFilepath -ErrorAction Stop
                    $ValidInput = $true
                } catch {
                    Write-HostStatusMsg -Type error -Message "Invalid path. Did you specify the full path?"
                }
            }
        }

        # Set output filename
        $Time = Get-Date -Format "yyyyMMddHHmmss"
        $OutputFilePath = "$PSScriptRoot\cracked_dictionary_$Time.txt"
        [void](New-Item -Itemtype File -Path $OutputFilePath)

        # Perform dictionary attack
        $Feedback = "Starting dictionary attack with the following parameters:`n"
        $Feedback += "Victim File    : $VictimFilepath`n"
        $Feedback += "Hash Algorithm : $HashAlgorithm`n"
        $Feedback += "Dictionary     : $DictionaryFilepath`n"
        $Feedback += "Results File   : $OutputFilePath"
        Write-HostStatusMsg -Type status -Message $Feedback

        $Time = Get-Date
        foreach ($Word in $Dictionary) {
            $HashedWord = Get-HashedValue -Plaintext $Word -HashType $HashAlgorithm
            if (!($HashedWord -eq "")) {
                Compare-Hashes -Plaintext $Word -Hash $HashedWord -OutputFilePath $OutputFilePath
            }
            if ($Script:TotalPasswordsCracked -eq $VictimFileLength) {
                Write-HostStatusMsg -Type status -Message "All hashes in $VictimFilepath cracked!"
                break
            }
        }
    }
    default {Write-HostStatusMsg -Type error -Message "Unexpected bad input!"; exit}
}

$TimeElapsed = New-TimeSpan -Start $Time -End $(Get-Date)
Write-HostStatusMsg -Type status -Message "Results saved to $OutputFilePath"
Write-HostStatusMsg -Type status -Message "Time Elapsed: $TimeElapsed"
Write-HostStatusMsg -Type status -Message "Passwords Cracked: $Script:TotalPasswordsCracked"
Write-Host "END   : " -ForegroundColor Red -NoNewline
Read-Host "Script complete. Press ENTER to exit"
