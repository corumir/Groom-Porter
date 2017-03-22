# Groom-Porter
Runs quality controls checks and performs [very basic] metrics on a YARA file.  Its a very simple attempt to understand and gather information on the organization of rules and their interactions.  It also provides some basic syntax checks and points out obvious issues with efficiency, such as excessive duplication of strings or an overabundance of regex.

### Groom-Porter usage
python Groom-Porter.py yarafile.yar [optional argument] skip

By default, Groom-Porter will attempt to compile the yara file passed as the first argument.  If that causes an issue or is something you do not want, pass it the word 'skip' to, well, skip this step.

### What Groom-Porter is built to catch
* duplicate rules
* rule count (all)
* rule count for global and private rules
* top 20 used strings and their counts
* count of regex, hex string, unicode (fullword keyword)
* count of keywords employed
* count of condition line logic structures 


