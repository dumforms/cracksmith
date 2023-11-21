# Define constants
$LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
$UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
$NUMBERS = "1234567890"
$SPECIAL = "!@#$%^&*(),./?;:[]{}-+_=\|<>~```"`'"
$OUTPUT_FILENAME = "$PWD\hashes.txt"
#Write-Host $PWD
## Grading Criteria
$GOOD_ENTROPY = 60
$BEST_ENTROPY = 90
$GOOD_LENGTH = 8
$BEST_LENGTH = 16
$GOOD_MIN_CONSEC = 4
$BEST_MIN_CONSEC = 2
$GOOD_NUM_CHARS = 1
$BEST_NUM_CHARS = 2

# Get user input
$password = Read-Host "Enter a password to test"

# Function definitions

# Find-Characters returns an array:
#  - $return_array[0] is the count of characters that are present in both $s and $c.
#  - $return_array[1] is the longest series of consecutive characters in $s.
#  - $return_array[2] is the number of unique characters from $c present in $s
function Find-Characters {
    param (
        [string]$s,
        [string]$c
    )
    $input_string = $s
    $char_list = $c
#    Write-Host "$input_string | $char_list"

    $total_chars = 0
    $prev_char = ""
    $unique_char_list = ""
    $count_consec = 1
    $total_consec = 0

    foreach ($char in $input_string.ToCharArray()) {
#        Write-Host "$char, $total_chars, $prev_char, $count_consec, $total_consec"
        if ($char_list.Contains($char)) {
            $total_chars ++
            if ($char -eq $prev_char) {
                $count_consec ++
                if ($count_consec -gt $total_consec) {
                    $total_consec = $count_consec
                }
            } else {
                $count_consec = 1
            }
            if (!$unique_char_list.Contains($char)) {
                $unique_char_list = $unique_char_list + $char
            }
        }
        $prev_char = $char
    }

    $return_array = @($total_chars, $total_consec, $unique_char_list.Length)
#    Write-Host $return_array
    Write-Output $return_array
}

# Compare-Parameters returns a string:
#  - "STRONG" if the integer $value meets or exceeds the $best threshold; else:
#  - "FAIR" if the $value meets or exceeds the $good threshold; else:
#  - "POOR" if neither of the prior conditions are met
function Compare-Parameters {
    param (
        [int]$value,
        [int]$best,
        [int]$good
    )
    $return =
    switch ($value) {
        {$_ -ge $best} {"STRONG"<#; Write-Host "$value | $best | $good"#>;break}
        {$_ -ge $good} {"FAIR"<#; Write-Host "$value | $best | $good"#>; break}
        default {"POOR"}
    }

#    Write-Host $return
    Write-Output $return
}

# Basic stats
## Password length
$length = $password.Length

## Lowercase stats (number of chars, number of consecutive chars, number of unique chars, boolean)
$stats_lc = Find-Characters -s $password -c $LOWERCASE_LETTERS
$count_lc = $stats_lc[0]
$consec_lc = $stats_lc[1]
$unique_lc = $stats_lc[2]
$contains_lc = ($count_lc -gt 0)

## Uppercase stats (number of chars, number of consecutive chars, number of unique chars, boolean)
$stats_uc = Find-Characters -s $password -c $UPPERCASE_LETTERS
$count_uc = $stats_uc[0]
$consec_uc = $stats_uc[1]
$unique_uc = $stats_uc[2]
$contains_uc = ($count_uc -gt 0)

## Number stats (number of chars, number of consecutive chars, number of unique chars, boolean)
$stats_num = Find-Characters -s $password -c $NUMBERS
$count_num = $stats_num[0]
$consec_num = $stats_num[1]
$unique_num = $stats_num[2]
$contains_num = ($count_num -gt 0)

## Spceial char stats (number of chars, number of consecutive chars, number of unique chars, boolean)
$stats_special = Find-Characters -s $password -c $SPECIAL
$count_special = $stats_special[0]
$consec_special = $stats_special[1]
$unique_special = $stats_special[2]
$contains_special = ($count_special -gt 0)

# Avanced stats
## Entropy (Formula: E = log[base 2](R^L), where R is possible chars and L is length)
$possible_unique_chars = 0
if ($contains_lc) {
    $possible_unique_chars += $LOWERCASE_LETTERS.Length
}
if ($contains_uc) {
    $possible_unique_chars += $UPPERCASE_LETTERS.Length
}
if ($contains_num) {
    $possible_unique_chars += $NUMBERS.Length
}
if ($contains_special) {
    $possible_unique_chars += $SPECIAL.Length
}
$entropy = [Math]::Log([Math]::Pow($possible_unique_chars, $length), 2)
## Round to one decimal
$entropy = [Math]::Round($entropy, 1)

#Write-Host "$unique_lc | $unique_uc | $unique_num | $unique_special"
# Grading Formulas
$length_grade = Compare-Parameters -value $length -best $BEST_LENGTH -good $GOOD_LENGTH
$entropy_grade = Compare-Parameters -value $([Math]::Round($entropy)) -best $BEST_ENTROPY -good $GOOD_ENTROPY
$lc_grade = Compare-Parameters -value $count_lc -best $BEST_NUM_CHARS -good $GOOD_NUM_CHARS
$uc_grade = Compare-Parameters -value $count_uc -best $BEST_NUM_CHARS -good $GOOD_NUM_CHARS
$num_grade = Compare-Parameters -value $count_num -best $BEST_NUM_CHARS -good $GOOD_NUM_CHARS
$special_grade = Compare-Parameters -value $count_special -best $BEST_NUM_CHARS -good $GOOD_NUM_CHARS

# Hashes
#  - write the string to a stream and compute that hash, according to MS docs
$stringAsStream = [System.IO.MemoryStream]::new()
$writer = [System.IO.StreamWriter]::new($stringAsStream)
$writer.write($password)
$writer.Flush()
$stringAsStream.Position = 0

$hash_md5 = Get-FileHash -InputStream $stringAsStream -Algorithm MD5 | Select-Object Hash | Out-String -Stream | Select-Object -Skip 3
$hash_sha1 = Get-FileHash -InputStream $stringAsStream -Algorithm SHA1 | Select-Object Hash | Out-String -Stream | Select-Object -Skip 3
$hash_sha256 = Get-FileHash -InputStream $stringAsStream -Algorithm SHA256 | Select-Object Hash | Out-String -Stream | Select-Object -Skip 3

# Console output
#Write-Host "Password Analyzed!"
Write-Host
"Statistic`t| Value`t`t| Grade
----------------+---------------+----------
Length`t`t| $length`t`t| $length_grade
Entropy`t`t| $entropy`t`t| $entropy_grade
Lowercase`t| $count_lc`t`t| $lc_grade
Uppercase`t| $count_uc`t`t| $uc_grade
Numbers`t`t| $count_num`t`t| $num_grade
Special`t`t| $count_special`t`t| $special_grade

MD5:`t$hash_md5
SHA1:`t$hash_sha1
SHA256:`t$hash_sha256"

# Save MD5 hash to file
$save_pass = Read-Host "Save MD5 hash to file (y/n)"
if ($save_pass.ToLower() -eq "y") {
    try {
        New-Item -Itemtype File -Path $OUTPUT_FILENAME -ErrorAction Stop | Out-Null
        Add-Content -Path $OUTPUT_FILENAME -Value $hash_md5
        Write-Host "Password hash saved to new file!"
    }
    catch [System.IO.IOException] {
        Add-Content -Path $OUTPUT_FILENAME -Value "$hash_md5"
        Write-Host "Password hash saved to existing file!"
    }
} else {
    Write-Host "Password hash discarded."
}

# Hold console window open until user exits
Read-Host "Script complete. Press ENTER to exit"