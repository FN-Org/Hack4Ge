#/home/niky/Documents/Hack4Ge/Hack4Ge-master/sqli/sqli-1/src/db.py

import re
import os
import sys
        
#FIND VULNERABLE
def find_vulnerable(string):
    matches_1 = re.findall(r'% {0,2}s {0,2}\' {0,2}" {0,2}, \( {0,2}(?:...) {0,2}, {0,2}\)', string, re.IGNORECASE)
    matches_2 = re.findall(r'% {0,2}\( {0,2}(?:...) {0,2}\) {0,2}s {0,2}" {0,2}, {0,2}{\'(?:...)\': {0,2}(?:...) {0,2}}', string, re.IGNORECASE)
    matches_3 = re.findall(r'= {0,2}\? {0,2}" {0,2}, {0,2}(?:...)', string, re.IGNORECASE)
    if matches_1:
        return False
    elif matches_2:
        return False
    elif matches_3:
        return False
    elif "WHERE" not in string:
        return False
    else:
        return True

#SAVE QUERY
def extract_select_query(file_path):
    with open(file_path, 'r') as f:
        contents = f.read()
    f.close()
    query_list = []
    i = 0
    cnt=0
    prec_end_index = 0
    while True:
        start_index = contents.find("SELECT", prec_end_index)
        if start_index == -1:
            #print("No SELECT query found in file.")
            break
        temp_end_index = contents.find(")", start_index)
        end_index = contents.find("\n", temp_end_index)
        if end_index == -1:
            #print("No closing parenthesis found after SELECT query.")
            break
        
        query_text = contents[start_index:end_index].strip()
        
        for j in range(prec_end_index, end_index):
            if contents[j]=="\n":
                cnt +=1
        prec_end_index=end_index
        query_list.append(query_text)
        if find_vulnerable(query_list[i]):
            #find_row
            #r = find_row(file_path, query_list[i])
            #matching_line_numbers = [i+1 for i, line in enumerate(lines) if query_list[i] in line]
            print(file_path, " ", "approx:",cnt, " SQLI")
        i +=1
        #contents = contents.replace(query_text, " ")

#PROGRAM.PY DETECTOR
def find_py_files(directory_path):
    if directory_path.endswith('.py'):
        extract_select_query(directory_path)
    else:
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                if filename.endswith('.py'):
                    full_path = os.path.join(dirpath, filename)
                    extract_select_query(full_path)

#MAIN
nome_script, path = sys.argv
find_py_files(path)
#for elements in query_list:
#    print(elements)