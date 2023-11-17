# objdebug 

Hacked up tool I use to inspect Go (native) object files for troubleshooting, 
bugfixing and learning. Heavily dependent on Go internal packages. 
Fills a nice gap between nm, objdump, and debugger (dlv).  

Not maintained.

## Installation 

Needs to be extracted into the go source directory:

go/src/cmd

Then its:

```
go build 
```

## Usage

Can read .a (archive) and .o (object files) files, without needing to specify. 

```
objdebug [-relocs] [-s=<regexsyms>] <file>
```

Customise to debug the sitaution as needed.


