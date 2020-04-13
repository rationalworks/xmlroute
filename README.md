# xmlroute

This project is a copy of https://www.elifulkerson.com/projects/xmlroute.php with a few additional modification.

## How to run:
```
xmlroute www.google.com
```
If you are intrested only in the utility not in the source code you can download from the Release folder.

## Description:
xmlroute.exe is a console utility that performs the same function as 'tracert.exe'. The key difference being that it formats its output in XML. This is probably not particularly useful unless you require traceroute data as input to another program: nice, orderly XML is superior to the normal traceroute output in that case.

In the interest of orderly output, this program ceases all tracerouting activities at the first sign of a timeout. The idea is to get known good or known bad data rather than the iffy results that can be gotten from a few dropped packets somewhere in the middle.

## Changes:
* It has been modified to continue even if one or more node is un-reachable. 
* The project has been converted to visual studio project.
