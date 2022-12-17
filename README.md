# Rainbow-Table
A rainbow table is an efficient way to store data that has been computed in advance to facilitate cracking passwords.
If you are unfamiliar with rainbow tables I highly suggest reading Wikipedia's article on them.
https://en.wikipedia.org/wiki/Rainbow_table

## Works with SHA-256 hashes

### To prevent against rainbow table attacks, simply salt your hashes (mmm yummy)

## Instructions
WARNING: This does not seem to work on my personal computer, but works on my UNIX server. On my Windows 10 PCs, I get "UnicodeEncodeError: 'charmap' codec can't encode character '\u0e16' in position 15: character maps to <undefined>"
Download a wordlist of plaintext passwords. From the internet.
Here is a good list of many wordlists. I suggest using the RockYou list. https://github.com/danielmiessler/SecLists/tree/master/Passwords

## Computer each hash chain from a starting word
`python3 rainbowtable.py --mode generate --num-chains 500000 -k 100` in your shell
You can change the number of chains and length of the chains to however you see fit. Altering the numbers will result in better or worse results.
This will generate a rainbowtable.txt file

## Crack the hashes
Run the command `python3 hw2.py --mode crack --num-chains 500000 -k 100 --rt-file rainbowbowtable.txt --hash-file hashes_test.txt` 
--hash-file hashes_test.txt = *YOUR SHA256 PASSWORD HASHES TO CRACK*

The CLI will print out each hash with the corresponding password on the right
