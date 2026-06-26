## Pwninit Intro
Pwninit is a tool to automate setup for binary exploitation. It's main features include auto linking Libc's, fixing paths and fetching linkers

### Installation
`cargo install pwninit`

### Using it 
Just run pwninit in the current directory with the binary and libc and it will auto detect the files and do its magic

Pwninit also takes arugments such as `--bin` and `--libc` if you want to specify these
`pwninit --bin ret2libc --libc libc-2.31.so`
