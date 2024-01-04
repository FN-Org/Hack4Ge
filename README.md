# Hack4Ge_AFN-Security

Team: AFN-Security

Members: Alessandro Poggi, Federico Garau, Nicolò Trebino

Look at this GitHub repository for more information about the project: https://github.com/talos-security/Hack4Ge-2023


## Requirments

This application is written in Python.
The technology used is:

-Python3.x

## Setup

Only the default libraries are used.

## Input
Type in the bash as follows to run the application inside the Project folder:
```bash
python3 parser.py /your-application-dir
```

## Output
The program will print on the console files with SQLI or SSTI vulnerability.
The output should be as follows:
```
FILE   ROW   VULNERABILITY   
/home/project/test-ssti.py approx. 34 STTI
/home/project/test-sqli.py approx. 80 SQLI
```
