import re
import os
import sys

#SQLI
#FIND VULNERABLE
def find_vulnerable_sqli(string):
    matches_1 = re.findall(r'% {0,10}s {0,10}\' {0,10}" {0,10}, \( {0,10}(?:.){1,30} {0,10}, {0,10}\)', string, re.IGNORECASE)
    matches_2 = re.findall(r'% {0,10}\( {0,10}(?:.){1,30} {0,10}\) {0,10}s {0,10}" {0,10}, {0,10}{\'(?:.){1,30}\': {0,10}(?:.){1,30} {0,10}}', string, re.IGNORECASE)
    matches_3 = re.findall(r'= {0,10}\? {0,10}" {0,10}, {0,10}(?:.){1,30}', string, re.IGNORECASE)
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

#SQLI
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
            break
        temp_end_index = contents.find(")", start_index)
        end_index = contents.find("\n", temp_end_index)
        if end_index == -1:
            break
        
        query_text = contents[start_index:end_index].strip()
        
        for j in range(prec_end_index, end_index):
            if contents[j]=="\n":
                cnt +=1
        prec_end_index=end_index
        query_list.append(query_text)
        if find_vulnerable_sqli(query_list[i]):
            print(file_path, " ", "approx.",cnt, " SQLI")
        i +=1

#SSTI
#FIND VULNERABLE
def find_vulnerable_ssti(string):
    matches_1 = re.findall(r'\$ {0,10}{ {0,10}(?:.){1,30} {0,10}}', string, re.IGNORECASE)
    matches_2 = re.findall(r'\$ {0,10}{ {0,10}(?:.){1,30} {0,10}\| {0,10}h {0,10}}', string, re.IGNORECASE)
    matches_3 = re.findall(r'{ {0,10}{ {0,10}(?:.){1,30} {0,10}\| {0,10}escape {0,10}} {0,10}}', string, re.IGNORECASE)
    matches_4 = re.findall(r'{ {0,10}% {0,10}autoescape {0,10}true {0,10}% {0,10}}  {0,5}< {0,10}(?:.){1,5}> {0,10}{ {0,10}{ {0,10}(?:.){1,30} {0,10}} {0,10}} {0,10}< {0,10}(?:.){1,5} {0,10}> {0,10}{ {0,10}% {0,10}endautoescape {0,10}% {0,10}}', string, re.IGNORECASE)
    if matches_1:
        return False
    elif matches_2:
        return False
    elif matches_3:
        return False
    elif matches_4:
        return False
    else:
        return True

#SSTI
#SAVE FORM
def extract_select_form(file_path):
    with open(file_path, 'r') as f:
        contents = f.read()
    f.close()
    form_list = []
    i = 0
    cnt=0
    prec_end_index = 0
    while True:
        start_index = contents.find("</form>", prec_end_index)
        if start_index == -1:
            break
        temp_end_index = contents.find("</html>", start_index)
        end_index = contents.find("\n", temp_end_index)
        if end_index == -1:
            break
        
        form_text = contents[start_index:end_index].strip()
        
        for j in range(prec_end_index, end_index):
            if contents[j]=="\n":
                cnt +=1
        prec_end_index=end_index
        form_list.append(form_text)
        if find_vulnerable_ssti(form_list[i]):
            print(file_path, " ", "approx.",cnt, " SSTI")
        i +=1

#PROGRAM.PY DETECTOR
def find_py_files(directory_path):
    if directory_path.endswith('.py'):
        extract_select_query(directory_path)
        extract_select_form(directory_path)
    else:
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                if filename.endswith('.py'):
                    full_path = os.path.join(dirpath, filename)
                    extract_select_query(full_path)
                    extract_select_form(full_path)

#MAIN
nome_script, path = sys.argv
print("FILE   ROW   VULNERABILITY")
find_py_files(path)