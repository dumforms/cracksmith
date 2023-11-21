## TODO ##
# - Add regex analysis of passwords to check for date formats

## CONSTANTS AND DEFAULT SETTINGS##
# General defaults
Set-Variable -name AsciiBanner -option Constant -value ([string](
" _____ _             ______                __   ____            _ _   _     " + "`n" +
"|_   _| |__   ___   / ____/________ ______/ /__/ ___| _ __ ___ (_) |_| |__  " + "`n" +
"  | | | '_ \ / _ \ / /   / ___/ __ '/ ___/ //_/|___ \| '_ ' _ \| | __| '_ \ " + "`n" +
"  | | | | | |  __// /___/ /  / /_/ / /__/ ,<,   ___) | | | | | | | |_| | | |" + "`n" +
"  |_| |_| |_|\___|\____/_/   \__,_/\___/_/|_|  \____/|_| |_| |_|_|\__|_| |_|" + "`n" +
"   Will your password survive the heat of the forge?                        " + "`n"
))
Set-Variable -name DefaultFlag -option Constant -value ([string]"")
Set-Variable -name OperationModes -option Constant -value ([string](
    "a) Brute Force Attack" + "`n" +
    "b) Dictionary Attack" + "`n" +
    "c) Password Analyzer" + "`n" +
    "d) Hash Generator"
))
Set-Variable -name DefaultOperationMode -option Constant -value ([string]"a")
Set-Variable -name DefaultVictimPath -option Constant -value ([string]"$PSScriptRoot\victim.txt")
Set-Variable -name DefaultOutputDirectory -option Constant -value ([string]"$PSScriptRoot\Results")
Set-Variable -name DefaultHashAlgorithm -option Constant -value ([string]"MD5")

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
Set-Variable -name DefaultMinimumLength -option Constant -value ([int]1)
Set-Variable -name DefaultMaximumLength -option Constant -value ([int]4)

# Dictionary attack defaults
Set-Variable -name DefaultDictionaryDirectory -option Constant -value (
    [string]"$PSScriptRoot\Dictionaries"
)
Set-Variable -name DefaultDictionaryPath -option Constant -value (
    [string]"$DefaultDictionaryDirectory\100k-most-used-passwords-NCSC.txt"
)

# Password analyzer constants
Set-Variable -name AnalyzerOutputFilePath -option Constant -value ([string]"$DefaultOutputDirectory\analyzed_hashes.txt")
Set-Variable -name GoodEntropy -option Constant -value ([int]60)
Set-Variable -name BestEntropy -option Constant -value ([int]90)
Set-Variable -name GoodLength -option Constant -value ([int]8)
Set-Variable -name BestLength -option Constant -value ([int]16)
Set-Variable -name GoodConsecutive -option Constant -value ([int]4)
Set-Variable -name BestConsecutive -option Constant -value ([int]2)
Set-Variable -name GoodNumberCharacters -option Constant -value ([int]1)
# Set-Variable -name BestNumberCharacters -option Constant -value ([int]($BestLength/5))
# Set-Variable -name GoodUniqueCharacters -option Constant -value ([int]($BestLength/10))
# Set-Variable -name BestUniqueCharacters -option Constant -value ([int]($BestLength/5))

# String hasher constants
Set-Variable -name DefaultInputPath -option Constant -value ([string]"$PSScriptRoot\input.txt")

## END CONSTANTS ##


## FUNCTIONS ##
function Write-HostStatusMessage {
<#
.SYNOPSIS
    Adds colored flag text to the beginning of console messages

.DESCRIPTION
    Write-HostStatusMessage is a funciton that displays a flag (such as ERROR or STATUS) in an associated color
    before printing the rest of the console output using the default Write-Host function.

.PARAMETER Type
    The name of the flag to set

.PARAMETER Message
    The string to print as plain text after the flag

.EXAMPLE
    Write-HostStatusMessage -Type status -Message "This is an example status message!"

.OUTPUTS
    None (writes to the console using Write-Host)
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
        "update" {Write-Host "UPDATE: " -ForegroundColor DarkMagenta -NoNewline; break}
    }
    Write-Host $Message
}


function Read-HostStatusMessage {
<#
.SYNOPSIS
    Adds colored flag text and can prompt the user to confirm or deny an action with a yes/no response.

.DESCRIPTION
    Read-HostStatusMessage is a function that displays a message to the user and waits for
    a response. It displays a gray "INPUT" flag at the beginning of the prompt. If the "boolean"
    message type is selected and the user inputs "y" or "yes" (case-insensitive), the
    function returns true. Otherwise, if the boolean message type is selecte, it returns false.
    In all other cases, it returns exactly what was received from from Read-Host.

.PARAMETER Type
    The type of message. Currently just switches between a yes/no prompt or a normal Read-Host prompt.

.PARAMETER Message
    The string with which to prompt the user

.EXAMPLE
    $DoWork = Read-HostStatusMessage -Type boolean -Message "Do work?"
    if ($DoWork) {#Do work here}

.EXAMPLE
    $UserInputString = Read-HostStatusMessage -Message "I want input"

.OUTPUTS
    A boolean value representing the user's affirmative or negative response.
#>
    param (
        [String]$Type = "",
        [Parameter(Mandatory)]
        [String]$Message
    )

    switch ($Type) {

        "boolean" {
            Write-Host "INPUT : " -ForegroundColor DarkGray -NoNewline
            $Response = Read-Host "$Message [y/n]"
            $Response = $Response.ToLower()
            $Response = (($Response -eq "y") -or ($Response -eq "yes"))
            break
        }

        default {
            Write-Host "INPUT : " -ForegroundColor DarkGray -NoNewline
            $Response = Read-Host $Message
        }

    }
    Write-Output $Response
    
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
    Relies on the script-level variable $VictimFileContent, which should be an array of hash strings
    that includes all yet-unmatched strings from the original input file.
#> 
    param (
        [Parameter(Mandatory)]
        [String]$Plaintext,
        [Parameter(Mandatory)]
        [String]$Hash,
        [Parameter(Mandatory)]
        [String]$OutputFilePath
    )

    foreach ($Line in $script:VictimFileContent) {
        if ($Hash -eq $Line) {
            $script:VictimFileContent = $script:VictimFileContent | Where-Object {$_ -notmatch $Hash}
            $script:TotalPasswordsCracked ++
            if ($Plaintext.Length -lt 8) {
                Write-HostStatusMessage -Type crack -Message "$Plaintext`t`t| $Hash"
                Add-Content -Path $OutputFilePath -Value "$Plaintext`t`t| $Hash"
            } else {    # $Plaintext.Length greater than or equal to 8
                Write-HostStatusMessage -Type crack -Message "$Plaintext`t| $Hash"
                Add-Content -Path $OutputFilePath -Value "$Plaintext`t| $Hash"
            }
            if ($script:TotalPasswordsCracked % 100 -eq 0) {
                $Message = "$script:TotalPasswordsCracked total passwords cracked!"
                Write-HostStatusMessage -Type update -Message $Message
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
        $Hash = ""
    }
    Write-Output $Hash
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


function Get-StringInfo {
<#
.SYNOPSIS
    Generate stats about a given string that are relevant to password analysis.
.DESCRIPTION
    Given an input string and a character set (as a string), determine:
     - The count of characters that are present in both strings
     - The longest series of consecutive characters from the set in the input string
     - The number of unique characters from the set in the input string

.PARAMETER InputString
    The string to perform analyses on

.PARAMETER CharacterSet
    The character set to use in the analysis

.EXAMPLE
    $StringStatsArray = Get-StringInfo -InputString "password" -CharacterSet "1234567890"

.OUTPUTS
    An array of integers that represent characteristics of the string.
     - $StringStatsArray[0] is the count of characters that are present in both strings.
     - $StringStatsArray[1] is the longest series of consecutive characters from the set in the input string.
     - $StringStatsArray[2] is the number of unique characters from the set in the input string.
#>
    param (
        [Parameter(Mandatory)]
        [string]$InputString,
        [Parameter(Mandatory)]
        [string]$CharacterSet
    )

    $TotalSharedCharCount = 0
    $PreviousCharacter = ""
    $UniqueCharacterList = ""
    $TempConsecutiveCount = 1
    $FinalConsecutiveCount = 0

    foreach ($Char in $InputString.ToCharArray()) {
        if ($CharacterSet.Contains($Char)) {
            $TotalSharedCharCount ++
            if ($Char -eq $PreviousCharacter) {
                $TempConsecutiveCount ++
                if ($TempConsecutiveCount -gt $FinalConsecutiveCount) {
                    $FinalConsecutiveCount = $TempConsecutiveCount
                }
            } else {
                $TempConsecutiveCount = 1
            }
            if (!$UniqueCharacterList.Contains($Char)) {
                $UniqueCharacterList = $UniqueCharacterList + $Char
            }
        }
        $PreviousCharacter = $Char
    }

    $ReturnArray = @($TotalSharedCharCount, $FinalConsecutiveCount, $UniqueCharacterList.Length)
    Write-Output $ReturnArray
}


function Compare-Parameters {
<#
.SYNOPSIS
    Return a string representation of the grade of a given value
.DESCRIPTION
    Given a (probably integer) value and two thresholds of quality, compares the value to the
    thresholds. Returns a string indicating that the value is either "POOR," "FAIR," or "STRONG."

.PARAMETER InputValue
    The value to compare against the benchmarks

.PARAMETER Best
    Values that are greater than or equal to this value will be graded "STRONG"

.PARAMETER Good
    Values that are less than $Best but greater than or equal to this value will be graded "FAIR"

.PARAMETER Invert
    If true, the grades will be assigned by a "less than or equal to" comparison instead.
    Used when a lower value is better. Defaults to false if not supplied.

.EXAMPLE
    $LengthGrade = Compare-Parameters -InputValue $Length -Best $BEST_LENGTH -Good $GOOD_LENGTH

.OUTPUTS
    The predefined string indicating the grade
#>
    param (
        [Parameter(Mandatory)]
        [int]$InputValue,
        [Parameter(Mandatory)]
        [int]$Best,
        [Parameter(Mandatory)]
        [int]$Good,
        [bool]$Invert = $false
    )

    if ($Invert) {

        $Return =
        switch ($InputValue) {
            {$_ -le $Best} {"STRONG";break}
            {$_ -le $Good} {"FAIR"; break}
            default {"POOR"}
        }

    } else {

        $Return =
        switch ($InputValue) {
            {$_ -ge $Best} {"STRONG";break}
            {$_ -ge $Good} {"FAIR"; break}
            default {"POOR"}
        }

    }

    Write-Output $Return
}
## END FUNCTIONS ##


## MAIN PROGRAM ##
Write-Host $AsciiBanner

# Create Results directory if it does not already exist
if (!(Test-Path $DefaultOutputDirectory)) {
    [void](New-Item -ItemType Directory -Path $DefaultOutputDirectory)
}

do {
    # Clear script variables
    $Script:TotalPasswordsCracked = 0
    
    # Validate operation mode.
    # - If the default flag is provided, use the default operation mode.
    # - Otherwise, match the input to one of the valid types.
    $ValidInput = $false
    while (!$ValidInput) {
        Write-Host $OperationModes
        $OperationMode = Read-HostStatusMessage -Message "Select one of the above operation modes (a-d)"
        if ($OperationMode -eq $DefaultFlag) {
            $OperationMode = $DefaultOperationMode
            $ValidInput = $true
            Write-HostStatusMessage -Type status -Message "Defaulting to mode ($OperationMode)"
        } else {
            $OperationMode = $OperationMode.ToLower()
            switch ($OperationMode) {
                "a" {$ValidInput = $true; break}
                "b" {$ValidInput = $true; break}
                "c" {$ValidInput = $true; break}
                "d" {$ValidInput = $true; break}
                default {Write-HostStatusMessage -Type error -Message "Invalid mode selected."}
            }
        }
    }

    # Attack-only options
    if ($OperationMode -eq "a" -or $OperationMode -eq "b") {

        # Get victim filepath.
        # - If the default flag is provided, use the default path.
        # - If a root path is not provided, assume the local directory.
        # - If an extension is not provided, assume a .txt extension.
        # - Verify that the file can be read before leaving the input loop
        $ValidInput = $false
        while (!$ValidInput) {

            $VictimFilePath = Read-HostStatusMessage -Message "Name the victim file containing hashes to attack"
            if ($VictimFilePath -eq $DefaultFlag) {

                $VictimFilePath = $DefaultVictimPath
                Write-HostStatusMessage -Type status -Message "Defaulting to $VictimFilePath"
                try {
                    $VictimFileContent = Get-Content -Path $VictimFilePath -ErrorAction Stop
                    $ValidInput = $true
                } catch {
                    Write-HostStatusMessage -Type error -Message "Cannot find default victim file."
                }

            } else {

                if (!($VictimFilePath.Contains("/") -or $VictimFilePath.Contains("\"))) {
                    $VictimFilePath = "$PSScriptRoot\" + $VictimFilePath
                }

                if ($VictimFilePath -notmatch ".*?\.(\w{2,4})?$") {
                    $VictimFilePath += ".txt"
                } 

                try {
                    $VictimFileContent = Get-Content -Path $VictimFilePath -ErrorAction Stop
                    $ValidInput = $true
                } catch {
                    Write-HostStatusMessage -Type error -Message "Invalid path. Did you specify the full path?"
                }

            }

        }
    
        # Get victim file length (i.e., number of rows) from the contents
        $VictimFileLength = $VictimFileContent.Length

        # For attack modes, get hashing algorithm used on victim file (i.e., the algorithm to use during attack).
        # - If the default flag is provided, assume the default hash algorithm.
        # - Otherwise, match the input to one of the valid types.
        $ValidInput = $false
        while (!$ValidInput) {

            $HashAlgorithm = Read-HostStatusMessage -Message "Name the hash algorithm to use for the attack"
            if ($HashAlgorithm -eq $DefaultFlag) {

                $HashAlgorithm = $DefaultHashAlgorithm
                $ValidInput = $true
                Write-HostStatusMessage -Type status -Message "Defaulting to $HashAlgorithm"

            } else {

                switch ($HashAlgorithm.ToUpper()) {
                    "SHA1" {$ValidInput = $true; break}
                    "SHA256" {$ValidInput = $true; break}
                    "SHA384" {$ValidInput = $true; break}
                    "SHA512" {$ValidInput = $true; break}
                    "MACTRIPLEDES" {$HashAlgorithm = "MACTripleDES"; $ValidInput = $true; break}
                    "MD5" {$ValidInput = $true; break}
                    "RIPEMD160" {$ValidInput = $true; break}
                    default {Write-HostStatusMessage -Type error -Message "Unrecognized hash algorithm."; break}
                }

            }

        }

    }    

    # Validate additional parameters based on operation mode
    switch ($OperationMode) {

        "a" { ## Brute Force Attack ##

            # Get charset to use.
            # - If the default flag is provided, assume the default character set.
            # - Otherwise, match the input to one of the valid types.
            $ValidInput = $false
            while (!$ValidInput) {

                Write-Host $CharacterSets
                $CharacterSet = Read-HostStatusMessage -Message "Select one of the above character sets (a-h)"
                if ($CharacterSet -eq $DefaultFlag) {

                    $CharacterSet = $DefaultCharacterSet
                    $ValidInput = $true
                    $Message = "Defaulting to the following character set: `'$CharacterSet`'"
                    Write-HostStatusMessage -Type status -Message $Message

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
                        default {Write-HostStatusMessage -Type error -Message "Invalid character set option."}
                    }

                }

            }

            # Get length range
            # - If the default flag is provided, assume the default minimum length.
            # - Verify that the input is an integer before leaving the loop.
            # - For the maximum value, verify that it is larger than the minimum value.
            $ValidInput = $false
            while (!$ValidInput) {

                $MinLength = Read-HostStatusMessage -Message "Set the minimum expected password length"
                if ($MinLength -eq $DefaultFlag) {

                    $MinLength = $DefaultMinimumLength
                    $ValidInput = $true
                    Write-HostStatusMessage -Type status -Message "Defaulting to $MinLength"

                } else {

                    try {
                        $MinLength = [int]$MinLength
                        if ($MinLength -ge 0) {
                            $ValidInput = $true
                        } else {
                            Write-HostStatusMessage -Type error -Message "Mimimum length must be at least zero."
                        }                    
                    } catch [System.Management.Automation.PSInvalidCastException] {
                        Write-HostStatusMessage -Type error -Message "Minimum length must be a whole number."
                    }

                }

            }

            $ValidInput = $false
            while (!$ValidInput) {

                $MaxLength = Read-HostStatusMessage -Message "Set the maximum expected password length"
                if ($MaxLength -eq $DefaultFlag) {

                    $MaxLength = $DefaultMaximumLength
                    $ValidInput = $true
                    Write-HostStatusMessage -Type status -Message "Defaulting to $MaxLength"

                } else {

                    try {
                        $MaxLength = [int]$MaxLength
                        if ($MaxLength -ge $MinLength) {
                            $ValidInput = $true
                        } else {
                            $Message = "Maximum length must be larger than minimum length."
                            Write-HostStatusMessage -Type error -Message $Message
                        }
                    } catch [System.Management.Automation.PSInvalidCastException] {
                        Write-HostStatusMessage -Type error -Message "Maximum length must be a whole number."
                    }

                }

            }

            # Set ouptut file name
            $Time = Get-Date -Format "yyyyMMddHHmmss"
            $OutputFilePath = "$DefaultOutputDirectory\cracked_bruteforce_$Time.txt"
            [void](New-Item -Itemtype File -Path $OutputFilePath)

            # Perform brute force attack
            $Feedback = "Starting brute force attack with the following parameters:`n"
            $Feedback += "Victim File    : $VictimFilePath`n"
            $Feedback += "Hash Algorithm : $HashAlgorithm`n"
            $Feedback += "Character Set  : $CharacterSet`n"
            $Feedback += "Length Range   : $MinLength - $MaxLength`n"
            $Feedback += "Results File   : $OutputFilePath"
            Write-HostStatusMessage -Type status -Message $Feedback

            $Time = Get-Date
            for ($CurrentLength = $MinLength; $CurrentLength -le $MaxLength; $CurrentLength ++) {

                if ($Script:TotalPasswordsCracked -eq $VictimFileLength) {

                    Write-HostStatusMessage -Type status -Message "All hashes in $VictimFilePath cracked!"
                    Write-HostStatusMessage -Type status -Message "Results saved to $OutputFilePath"
                    break

                }
                Write-HostStatusMessage -Type status -Message "Testing passwords of length $CurrentLength..."
                $params = @{
                    "CharacterSet" = $CharacterSet
                    "HashType" = $HashAlgorithm
                    "OutputFilePath" = $OutputFilePath
                    "Length" = $CurrentLength
                }
                New-BruteForceAttack @params

            }

        }

        "b" { ## Dictionary Attack ##

            # Get filepath to dictionary wordlist.
            # - If the default flag is provided, use the default path.
            # - If a root path is not provided, assume the local .\Dictionaries directory.
            # - If an extension is not provided, assume a .txt extension.
            # - Verify that the file can be read before leaving the input loop
            $ValidInput = $false
            while (!$ValidInput) {

                $Message = "Provide a path to the dictionary file to use"
                $DictionaryFilePath = Read-HostStatusMessage -Message $Message
                if ($DictionaryFilePath -eq $DefaultFlag) {

                    $DictionaryFilePath = $DefaultDictionaryPath
                    Write-HostStatusMessage -Type status -Message "Defaulting to $DictionaryFilePath"

                    try {
                        $Dictionary = Get-Content -Path $DictionaryFilePath -ErrorAction Stop
                        $ValidInput = $true
                    } catch {
                        Write-HostStatusMessage -Type error -Message "Cannot find default dictionary file."
                    }

                } else {

                    if (!($DictionaryFilePath.Contains("/") -or $DictionaryFilePath.Contains("\"))) {
                        $DictionaryFilePath = $DefaultDictionaryDirectory + "\" + $DictionaryFilePath
                    }

                    if ($DictionaryFilePath -notmatch ".*?\.(\w{2,4})?$") {
                        $DictionaryFilePath += ".txt"
                    }

                    try {
                        $Dictionary = Get-Content -Path $DictionaryFilePath -ErrorAction Stop
                        $ValidInput = $true
                    } catch {
                        $Message = "Invalid path. Did you specify the full path?"
                        Write-HostStatusMessage -Type error -Message $Message
                    }

                }

            }

            # Set output filename
            $Time = Get-Date -Format "yyyyMMddHHmmss"
            $OutputFilePath = "$DefaultOutputDirectory\cracked_dictionary_$Time.txt"
            [void](New-Item -Itemtype File -Path $OutputFilePath)

            # Perform dictionary attack
            $Feedback = "Starting dictionary attack with the following parameters:`n"
            $Feedback += "Victim File    : $VictimFilePath`n"
            $Feedback += "Hash Algorithm : $HashAlgorithm`n"
            $Feedback += "Dictionary     : $DictionaryFilePath`n"
            $Feedback += "Results File   : $OutputFilePath"
            Write-HostStatusMessage -Type status -Message $Feedback

            $Time = Get-Date
            foreach ($Word in $Dictionary) {

                $HashedWord = Get-HashedValue -Plaintext $Word -HashType $HashAlgorithm
                if (!($HashedWord -eq "")) {
                    Compare-Hashes -Plaintext $Word -Hash $HashedWord -OutputFilePath $OutputFilePath
                }

                if ($Script:TotalPasswordsCracked -eq $VictimFileLength) {
                    Write-HostStatusMessage -Type status -Message "All hashes in $VictimFilePath cracked!"
                    break
                }

            }

        }

        "c" { ## Password Analyzer ##

            # Get user input
            $Password = Read-HostStatusMessage -Message "Enter a password to test"

            # Calculate basic stats
            $Length = $Password.Length

            ## Lowercase stats
            $LowercaseStats = Get-StringInfo -InputString $password -CharacterSet $CharsetLowercase
            $LowercaseCount = $LowercaseStats[0]
            $ConsecutiveLowercase = $LowercaseStats[1]
            $UniqueLowercase = $LowercaseStats[2]
            $ContainsLowercase = ($LowercaseCount -gt 0)

            ## Uppercase stats
            $UppercaseStats = Get-StringInfo -InputString $password -CharacterSet $CharsetUppercase
            $UppercaseCount = $UppercaseStats[0]
            $ConsecutiveUppercase = $UppercaseStats[1]
            $UniqueUppercase = $UppercaseStats[2]
            $ContainsUppercase = ($UppercaseCount -gt 0)

            ## Number stats
            $NumberStats = Get-StringInfo -InputString $password -CharacterSet $CharsetNumbers
            $NumberCount = $NumberStats[0]
            $ConsecutiveNumbers = $NumberStats[1]
            $UniqueNumbers = $NumberStats[2]
            $ContainsNumbers = ($NumberCount -gt 0)

            ## Spceial char stats
            $SymbolStats = Get-StringInfo -InputString $password -CharacterSet $CharsetSymbols
            $SymbolCount = $SymbolStats[0]
            $ConsecutiveSymbols = $SymbolStats[1]
            $UniqueSymbols = $SymbolStats[2]
            $ContainsSymbols = ($SymbolCount -gt 0)

            # Calculate entropy (Formula: E = log[base 2](R^L), where R is possible chars and L is length)
            $PossibleUniqueCharacters = 0
            if ($ContainsLowercase) {
                $PossibleUniqueCharacters += $CharsetLowercase.Length
            }
            if ($ContainsUppercase) {
                $PossibleUniqueCharacters += $CharsetUppercase.Length
            }
            if ($ContainsNumbers) {
                $PossibleUniqueCharacters += $CharsetNumbers.Length
            }
            if ($ContainsSymbols) {
                $PossibleUniqueCharacters += $CharsetSymbols.Length
            }
            $Entropy = [Math]::Log([Math]::Pow($PossibleUniqueCharacters, $Length), 2)
            ## Round to one decimal
            $Entropy = [Math]::Round($Entropy, 1)

            # Calculate grades
            ## Length grade
            $params = @{
                "InputValue" = $Length
                "Best" = $BestLength
                "Good" = $GoodLength
            }
            $LengthGrade = Compare-Parameters @params

            ## Entropy grade
            $params = @{
                "InputValue" = $([Math]::Round($Entropy))
                "Best" = $BestEntropy
                "Good" = $GoodEntropy
            }
            $EntropyGrade = Compare-Parameters @params

            ## Basic grades
            $params = @{
                "InputValue" = $LowercaseCount
                "Best" = $($Length/5)
                "Good" = $GoodNumberCharacters
            }
            $LowercaseGrade = Compare-Parameters @params
            $params["InputValue"] = $UppercaseCount
            $UppercaseGrade = Compare-Parameters @params
            $params["InputValue"] = $NumberCount
            $NumberGrade = Compare-Parameters @params
            $params["InputValue"] = $SymbolCount
            $SymbolGrade = Compare-Parameters @params

            ## Consecutive character grades (each type)
            $params = @{
                "InputValue" = $ConsecutiveLowercase
                "Best" = $BestConsecutive
                "Good" = $GoodConsecutive
                "Invert" = $true
            }
            $ConsecLowerGrade = Compare-Parameters @params
            $params["InputValue"] = $ConsecutiveUppercase
            $ConsecUpperGrade = Compare-Parameters @params
            $params["InputValue"] = $ConsecutiveNumbers
            $ConsecNumberGrade = Compare-Parameters @params
            $params["InputValue"] = $ConsecutiveSymbols
            $ConsecSymbolGrade = Compare-Parameters @params

            ## Unique character grades (each type)
            $params = @{
                "InputValue" = $UniqueLowercase
                "Best" = $($Length/5)
                "Good" = $($Length/10)
            }
            $UniqueLowerGrade = Compare-Parameters @params
            $params["InputValue"] = $UniqueUppercase
            $UniqueUpperGrade = Compare-Parameters @params
            $params["InputValue"] = $UniqueNumbers
            $UniqueNumberGrade = Compare-Parameters @params
            $params["InputValue"] = $UniqueSymbols
            $UniqueSymbolGrade = Compare-Parameters @params

            # Generate Hashes
            $HashMD5 = Get-HashedValue -Plaintext $Password -HashType "MD5"
            $HashSHA1 = Get-HashedValue -Plaintext $Password -HashType "SHA1"
            $HashSHA256 = Get-HashedValue -Plaintext $Password -HashType "SHA256"

            # Console output
            $Feedback =  "================#=======#========`n"
            $Feedback += "Statistic       | Value | Grade`n"
            $Feedback += "----------------+-------+--------`n"
            $Feedback += "Length          | $Length`t| $LengthGrade`n"
            $Feedback += "Entropy         | $Entropy`t| $EntropyGrade`n"
            $Feedback += "Lowercase       | $LowercaseCount`t| $LowercaseGrade`n"
            $Feedback += "Uppercase       | $UppercaseCount`t| $UppercaseGrade`n"
            $Feedback += "Numbers         | $NumberCount`t| $NumberGrade`n"
            $Feedback += "Symbols         | $SymbolCount`t| $SymbolGrade`n"
            $Feedback += "================#=======#========`n"
            $Feedback += "MD5:`t$HashMD5`n"
            $Feedback += "SHA1:`t$HashSHA1`n"
            $Feedback += "SHA256:`t$HashSHA256`n"
            Write-Host $Feedback

            # Offer to display more detailed stats
            $DetailedStats = Read-HostStatusMessage -Type boolean -Message "Display more password details?"
            if ($DetailedStats) {

                $Feedback =  "================#=======#========`n"
                $Feedback += "Consecutive...  | Value | Grade`n"
                $Feedback += "----------------+-------+--------`n"
                $Feedback += "Lowercase       | $ConsecutiveLowercase`t| $ConsecLowerGrade`n"
                $Feedback += "Uppercase       | $ConsecutiveUppercase`t| $ConsecUpperGrade`n"
                $Feedback += "Numbers         | $ConsecutiveNumbers`t| $ConsecNumberGrade`n"
                $Feedback += "Symbols         | $ConsecutiveSymbols`t| $ConsecSymbolGrade`n"
                $Feedback += "================#=======#========`n"
                $Feedback += "Unique...       | Value | Grade`n"
                $Feedback += "----------------+-------+----------`n"
                $Feedback += "Lowercase       | $UniqueLowercase`t| $UniqueLowerGrade`n"
                $Feedback += "Uppercase       | $UniqueUppercase`t| $UniqueUpperGrade`n"
                $Feedback += "Numbers         | $UniqueNumbers`t| $UniqueNumberGrade`n"
                $Feedback += "Symbols         | $UniqueSymbols`t| $UniqueSymbolGrade`n"
                $Feedback += "================#=======#========"
                Write-Host $Feedback

            }

            # Offer to save password to a file
            $SavePassword = Read-HostStatusMessage -Type boolean -Message "Save MD5 hash to file?"
            if ($SavePassword) {

                try {
                    [void](New-Item -Itemtype File -Path $AnalyzerOutputFilePath -ErrorAction Stop)
                    Add-Content -Path $AnalyzerOutputFilePath -Value $HashMD5
                    $Message = "Password hash saved to new file $AnalyzerOutputFilePath."
                    Write-HostStatusMessage -Type status -Message $Message
                }
                catch [System.IO.IOException] {
                    Add-Content -Path $AnalyzerOutputFilePath -Value "$HashMD5"
                    $Message = "Password hash saved to existing file $AnalyzerOutputFilePath."
                    Write-HostStatusMessage -Type status -Message $Message
                }

            } else {
                Write-HostStatusMessage -Type status -Message "Password hash discarded."
            }

        }

        "d" { ## Hash Generator ##

            # Get the input filepath.
            # - If the default flag is provided, use the default path.
            # - If a root path is not provided, assume the local directory.
            # - If an extension is not provided, assume a .txt extension.
            # - Verify that the file can be read before leaving the input loop.
            $ValidInput = $false
            while (!$ValidInput) {

                $InputFilePath = Read-HostStatusMessage -Message "File containing passwords to hash"
                if ($InputFilePath -eq $DefaultFlag) {

                    $InputFilePath = $DefaultInputPath
                    Write-HostStatusMessage -Type status -Message "Defaulting to $InputFilePath"
                    try {
                        $InputFileContent = Get-Content $InputFilePath -ErrorAction Stop
                        $ValidInput = $true
                    } catch {
                        Write-HostStatusMessage -Type error -Message "Cannot find default input file."
                    }

                } else {

                    if (!($InputFilePath.Contains("/") -or $InputFilePath.Contains("\"))) {
                        $InputFilePath = "$PSScriptRoot\" + $InputFilePath
                    }

                    if ($InputFilePath -notmatch ".*?\.(\w{2,4})?$") {
                        $InputFilePath += ".txt"
                    }

                    try {
                        $InputFileContent = Get-Content $InputFilePath -ErrorAction Stop
                        $ValidInput = $true
                    } catch {
                        $Message = "Invalid path. Did you specify the full path?"
                        Write-HostStatusMessage -Type error -Message $Message
                    }

                }
                
            }

            # Get the hash algorithm to use on the input file
            # - If the default flag is provided, assume the default hash algorithm.
            # - Otherwise, match the input to one of the valid types.
            $ValidInput = $false
            while (!$ValidInput) {

                $HashAlgorithm = Read-HostStatusMessage -Message "Specify a hash algorithm"
                if ($HashAlgorithm -eq $DefaultFlag) {

                    $HashAlgorithm = $DefaultHashAlgorithm
                    $ValidInput = $true
                    Write-HostStatusMessage -Type status -Message "Defaulting to $HashAlgorithm"

                } else {

                    switch ($HashAlgorithm.ToUpper()) {
                        "SHA1" {$ValidInput = $true; break}
                        "SHA256" {$ValidInput = $true; break}
                        "SHA384" {$ValidInput = $true; break}
                        "SHA512" {$ValidInput = $true; break}
                        "MACTRIPLEDES" {$HashAlgorithm = "MACTripleDES"; $ValidInput = $true; break}
                        "MD5" {$ValidInput = $true; break}
                        "RIPEMD160" {$ValidInput = $true; break}
                        default {
                            Write-HostStatusMessage -Type error -Message "Unrecognized hash algorithm."
                            break
                        }
                    }

                }
                
            }

            # Get the output filepath.
            # - If the default flag is provided, create a new file with a unique name.
            # - If a root path is not provided, assume the local directory.
            # - If an extension is not provided, assume a .txt extension.
            # - If a new file with that path cannot be created, append content to the existing file.
            $ValidInput = $false
            while (!$ValidInput) {

                $OutputFilePath = Read-HostStatusMessage -Message "File in which to write the hashes"
                if ($OutputFilePath -eq $DefaultFlag) {

                    $Time = Get-Date -Format "yyyyMMddHHmmss"
                    $OutputFilePath = "$DefaultOutputDirectory\hashes_$($HashAlgorithm)_$Time.txt"
                    Write-HostStatusMessage -Type status -Message "Defaulting to the new file $OutputFilePath"
                    [void](New-Item -Itemtype File -Path $OutputFilePath)
                    $ValidInput = $true

                } else {

                    if (!($OutputFilePath.Contains("/") -or $OutputFilePath.Contains("\"))) {
                        $OutputFilePath = "$PSScriptRoot\" + $OutputFilePath
                    }

                    if ($OutputFilePath -notmatch ".*?\.(\w{2,4})?$") {
                        $OutputFilePath += ".txt"
                    }

                    try {
                        [void](New-Item -Itemtype File -Path $output_path -ErrorAction Stop)
                        $ValidInput = $true
                    } catch [System.IO.IOException] {
                        Add-Content -Path $output_path -Value "`n"
                        $ValidInput = $true
                    } catch {
                        $Message = "Invalid path. Did you specify the full path?"
                        Write-HostStatusMessage -Type error -Message $Message
                    }

                }
                
            }

            # Write the hash of each line in $InputFileContent to the output file
            $Message = "Generating hashes from `'$InputFilePath`' and saving to `'$OutputFilePath`'..."
            Write-HostStatusMessage -Type status -Message $Message
            $LineCount = 0
            foreach ($Line in $InputFileContent) {

                $LineCount ++
                $Hash = Get-HashedValue -Plaintext $Line -HashType $HashAlgorithm
                
                if ($Hash -eq "") {
                    $Message = "Could not convert $Line to $HashAlgorithm hash. Skipping..."
                    Write-HostStatusMessage -Type error -Message $Message
                } else {
                    Add-Content -Path $OutputFilePath -Value $Hash
                }

                switch ($LineCount) {
                    {[Math]::Abs($_ - (($InputFileContent.Length)/10)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "10% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length)/5)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "20% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*3)/10)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "30% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*2)/5)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "40% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length)/2)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "50% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*3)/5)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "60% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*7)/10)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "70% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*4)/5)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "80% complete"}
                    {[Math]::Abs($_ - (($InputFileContent.Length*9)/10)) -lt 1}
                        {Write-HostStatusMessage -Type status -Message "90% complete"}
                }

            }

        }

        default {Write-HostStatusMessage -Type error -Message "Unexpected bad input!"; exit}
    }

    # Attack only ending stats
    if ($OperationMode -eq "a" -or $OperationMode -eq "b") {

        $TimeElapsed = New-TimeSpan -Start $Time -End $(Get-Date)
        $AverageRate = [Math]::Round(($Script:TotalPasswordsCracked / $TimeElapsed.TotalSeconds), 1)
        Write-HostStatusMessage -Type status -Message "Attack complete. Results saved to $OutputFilePath"
        Write-HostStatusMessage -Type status -Message "Time Elapsed: $TimeElapsed"
        Write-HostStatusMessage -Type status -Message "Passwords Cracked: $Script:TotalPasswordsCracked ($AverageRate/s)"

    }
    
    # Ask user if they want to run the program again
    $Message = "Process complete. Do you want to run TheCrackSmith again?"
    $RunAgain = Read-HostStatusMessage -Type boolean -Message $Message
} while($RunAgain)
