import os
from os import path as op
import re

from pdfminer.high_level import extract_text
from pdfminer.layout import LAParams

def pdf2text(pdf_path, filter_length=5):
    raw_text = extract_text(pdf_path, laparams=LAParams(line_margin=0.8))
    text = regroup(raw_text)
    text = filtering(text, filter_length)
    return text

def filtering(raw_text, filter_length=5):
    lines = raw_text.split('\n')
    # remove the default link+page+date pattern when automaticly generated during html2pdf
    lines_filtered = []
    i = 0
    while i < len(lines):
        if lines[i] == 'https://www.secureworks.com/blog/bronze-president-targets-government-ofﬁcials':
            a = len(re.findall(r'^https://', lines[i]))>0
            aa = re.findall(r'^https://', lines[i])
            b = i + 1 < len(lines)
            c = len(re.findall(r'\d+/\d+', lines[i+1]))>0
            cc = re.findall(r'\d+/\d+', lines[i+1])
        condition_a = len(re.findall(r'^https://', lines[i]))>0
        if condition_a:
            next_i = i+1
            while next_i < len(lines):
                if lines[next_i] != '':
                    break
                next_i += 1
            condition_b = len(re.findall(r'^\d+/\d+$', lines[min(next_i, len(lines) - 1)])) > 0
            i_b = next_i
            next_i = next_i + 1
            while next_i < len(lines):
                if lines[next_i] != '':
                    break
                next_i += 1
            i_c = next_i
            condition_c = len(re.findall(r'\d+/\d+/\d+, \d+:\d+', lines[min(next_i, len(lines) - 1)])) > 0
            if condition_c:
                i =  i_c + 1
            elif condition_b:
                i = i_b + 1
            else:
                i = i + 1
            continue
        lines_filtered.append(lines[i])
        i += 1
    lines = lines_filtered

    # remove the short paragraphs
    lines_filtered = []
    continuous_blank_flag=False
    for line in lines:
        if continuous_blank_flag is False and line == '':
            lines_filtered.append('')
            continuous_blank_flag = True
        if len(line) >= filter_length:
            continuous_blank_flag = False
            lines_filtered.append(line)
        elif len(line) > 0:
            pass
            # print(line)    
    text = ''
    for line in lines_filtered:
        text = text + line + '\n'
    return text

def regroup(raw_text: str):
    raw_groups = raw_text.split('\n\n')
    groups = []
    f = open('debug.txt', 'w', encoding='utf-8')
    for r_g in raw_groups:
        # print(r_g, file=f)
        # print('\n'+'-'*100+'\n', file=f)
        # replaced '\n' in one group with ''
        g = r_g.replace('\n', '')
        groups.append(g)
    f.close()
    text = '\n\n'.join(groups)
    return text
            


def main():
    pdf_root_dir = 'base'
    save_text_dir = './text'
    error_pdf_path = './error_pdf.log'
    pdf_paths = {}
    for root, dirs, files in os.walk(pdf_root_dir):
        for file in files:
            if file.endswith('.pdf'):
                pdf_paths.update({file[:-4]: op.join(root, file)}) # remove suffix '.pdf'
    for pdf_name in pdf_paths.keys():
        try:
            text = pdf2text(pdf_paths[pdf_name])
            with open(op.join(save_text_dir, pdf_name+'.txt'), 'w', encoding='utf-8') as f:
                f.write(text)
        except:
            with open(error_pdf_path, 'a', encoding='utf-8') as f:
                f.write(pdf_name + '\n')
        

if __name__ == '__main__':
    main()