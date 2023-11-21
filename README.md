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
