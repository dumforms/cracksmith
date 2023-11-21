```
 _____ _             ______                __   ____            _ _   _     
|_   _| |__   ___   / ____/________ ______/ /__/ ___| _ __ ___ (_) |_| |__  
  | | | '_ \ / _ \ / /   / ___/ __ '/ ___/ //_/|___ \| '_ ' _ \| | __| '_ \ 
  | | | | | |  __// /___/ /  / /_/ / /__/ ,<,   ___) | | | | | | | |_| | | |
  |_| |_| |_|\___|\____/_/   \__,_/\___/_/|_|  \____/|_| |_| |_|_|\__|_| |_|
```
# Description
The CrackSmith is a simple password cracking project I developed to learn more
about PowerShell. I wrote three separate tools first, then pulled them all together
into one tool.  

`string_hasher.ps1` takes an input file of strings separated by line breaks, and
a hash type, and returns a file with a hash of each line. I found this useful
when generating mock password datasets to attack with the CrackSmith.  

`password_analyzer.ps1` takes a plaintext "password" and returns statistics about
it, including length and entropy. Each value is given a grade (POOR, FAIR, or STRONG)
based on constants set in the code. Upon request, the tool will generate more detailed
statistics about the arrangement of characters in the password.  

`password_cracker.ps1` performs brute force or dictionary attacks against a specified
file. Several parameters for each attack type can be set by the user.  

`cracksmith.ps1` combines all three of the above tools. I made significant revisions to
deduplicate the code and implement PowerShell best practices. Every user input will
reject bad values and has a set default that it will fall back to if an empty string
is provided.

# Input Formatting
The CrackSmith attempts to be as user-friendly as possible. When requesting input,
it will make assumptions if certain information is excluded. If no input is provided
for a prompt, it will fall back to a default value. In every case, if the final value
does not exist or is insufficient, an error will be returned and the user will be prompted
for new input.

## File Paths
- If a full path is provided, that path will be tested and used if it exists
- If a name with no directory information (i.e., no `\` or `/`) is provided, TheCrackSmith
will assume the file is located in the same directory that itself is located in (NOT the
directory from which it was executed)
- If the path does not end in a file extension, `.txt` will be assumed

For example, if TheCrackSmith recieves `victim` as a path input, it will translate that into
`C:\...\victim.txt`

## Numbers
Inputs that require numbers will reject any string that cannot be typecast into an integer

## Lists
Inputs based on lists (e.g., pick an option from a-f) are case-insensitive, and will reject
any string that does match one of the available options

## Defualts
If an empty or null string is received as the input, a the input will be replaced with a default
value declared at the start of the file. All defaults are declared as constants, so the code may
be easily modified to use different values. There is also a `DefaultFlag` variable so that a
custom string may be set which the script will acknowledge as equivalent to an empty input,
triggering the default value.

# Acknowledgements

## PowerShell Best Practices
The code in the final cracksmith tool conforms to many of the best practices described
here [https://github.com/PoshCode/PowerShellPracticeAndStyle/tree/master] including
line length and variable naming. Credit to Don Jones, Matt Penny, Carlos Perez,
Joel Bennett, and the PowerShell Community for working to develop these standards.

## Dictionary Lists
The dictionary attack needs a dictionary. I found the SecLists repository
[https://github.com/danielmiessler/SecLists/tree/master] to contain a number of useful
dictionary files in formats that can be plugged directly into my tool.
