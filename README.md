pth-toolkit
===========

A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems

The master branch is compiled for amd64, the final goal will be to cross compile these tools to every possible architecture 

Currently this repo provides the following patched tools/utilities:
================================================
- winexe
- wmic 
- wmis
- rpcclient
- smbclient
- smbget
- net

Requirements
============

- ```sh``` 


All tools were tested on a bare bones Arch linux install with only the `base` package.  


When would this be useful?
=========================
- When your rocking a custom pentesting OS and you don't want to go through the agony of compiling and patching these tools yourself
- For post-exploitation to pivot to a Windows box/domain from a compromised *nix host! Just clone this repo or download the tarball and your ready to pass all the hashes!


