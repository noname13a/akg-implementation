import os.path as op
import os
from pprint import pprint
import time
import copy
import asyncio
from concurrent.futures import ThreadPoolExecutor
import re
import json
import argparse

import tiktoken
import openai
import numpy
import nltk
import numpy as np

from template import attack_graph_template
from template import Tactic_label_order
from openai import OpenAI


# gpt系列
openai_api_key = 'XXX'
openai_api_base = 'XXX'
current_model = 'XXX'



client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)



tactic_num = 1000

def num_tokens_from_string(string: str, model_name: str) -> int:
    """Returns the number of tokens in a text string."""
    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except:
        encoding = tiktoken.encoding_for_model('gpt-4o')

    num_tokens = len(encoding.encode(string))
    return num_tokens



def async_wrap(func, args):
    return asyncio.to_thread(func, **args)

def line2dict(line: str):
    # move the num of line if exists
    strings = line.replace('\n', '')
    strings = re.sub(r'^\d+\.', '', strings).strip()
    strings = re.sub(r'^\*', '', strings).strip()
    strings = strings.split(';')
    if len(strings) != 4:
        print("Format is wrong, line is skipped:")
        print(line, '\n')
        return None
    Sub_block = strings[0].strip()
    Obj_block = strings[2].strip()
    d = {
        "Subject" : Sub_block.split('(')[0],
        "SubjectType" : Sub_block.split('(')[-1].replace(')', ''),
        "Relation": strings[1].strip(),
        "Object": Obj_block.split('(')[-1].replace(')', ''),
        # "SentenceNums": []
    }
    # try:
    #     nums = re.split(' |-|,', strings[3])
    #     for n in nums:
    #         if n=='':  
    #             continue
    #         d["SentenceNums"].append(int(n))
    # except: 
    #     print('Number can not be transfered correctly with line (skipped):')
    #     print(line)
    #     return None
    return d

def dict2line(dict, joint_char=' ; ', no_num=False):
    line = dict["Subject"] + joint_char + dict["Relation"] + joint_char + dict["Object"] 
    if no_num is True:
        return line
    line = line + joint_char
    for n in dict["SentenceNums"]:
        line =  line + str(n) + ' '
    return line

def check_triplet(triplet:dict):
    keys = ['Subject', 'SubjectType', 'Relation', 'Object', 'ObjectType']
    for key in keys:
        if triplet.get(key) is None:
            triplet.update({key: 'Others'})
    return triplet

def openai_usage2dict(usage):
    usage_dict = {
        "prompt_tokens": usage["prompt_tokens"],
        "completion_tokens": usage["completion_tokens"],
        "total_tokens": usage["total_tokens"]
    }
    return usage_dict

def split_sentences(text: str):
    lines = text.splitlines()
    sents = []
    for line in lines:
        if line == '':
            continue
        sents.extend(nltk.sent_tokenize(line))
    return sents

def request_attack_graph(bags, tactic='None', model= current_model, temperature=0, max_token=120000):
    # split sents
    if len(bags) == 0:
        raise Exception('attack graph extractor length of bags list is 0')

    bag_text = ''
    id2name = {}
    for bag in bags:
        text = bag['text']
        sents = split_sentences(text)
        numbered_text_list = [] 
        for idx, sent in enumerate(sents):
            numbered_text_list.append(str(idx) + ': ' + sents[idx])
        numbered_text = '\n'.join(numbered_text_list) # not used
        bag_text = bag_text + 'article {}:\n'.format(bag['file_id']) + text + '\n\n'

        # update id2name mapping
        id2name.update({bag['file_id']: bag['file_name']})


    messages, tools = attack_graph_template(bag_text)
    # show messages
    '''for m in messages:
        print(m['content'])
    assert 0'''
    tool_choice = {
        "type": "function",
        "function": {
            "name": tools[0]['function']['name']
        }
    }


    num_token = 0
    for item in messages:
        num_token += num_tokens_from_string(item["content"], model)
    if num_token > max_token:
        print("Messages is skipped for reaching the maximum of the input token")
        return None      
    while True:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools = tools,
                tool_choice= tool_choice,
                temperature=temperature,
            )
            # result = response["choices"][0]["message"]["content"]
            # finish_reason = response["choices"][0]["finish_reason"]
            # usage = openai_usage2dict(response["usage"])
            # response_time = round(response.response_ms / 1000, 2)
            related_sents = {}
            #arguments = response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            if response.choices[0].message.tool_calls is None:
                id_from_first_bag = list(id2name.keys())[0]
                text_content = response.choices[0].message.content
                # print(text_content)
                arguments_dict = {
                    'triplets' : []
                }
                for line in text_content.split('\n'):
                    try:
                        d = line2dict(line)
                        d.update({'file_id': id_from_first_bag})
                        # add fake technique label
                        d.update({'technique' : ['T0000-Fake Technique']})
                        arguments_dict['triplets'].append(d)
                    except:
                        pass
                arguments = json.dumps(arguments_dict)
            else:
                arguments = response.choices[0].message.tool_calls[0].function.arguments

            try:
                parse_result = json.loads(arguments)
                # deal with the arguments output
                triplets = parse_result['triplets']
                result = []
                for triplet in triplets:
                    # map the file id to the file name
                    file_id = triplet['file_id']
                    file_name = id2name[file_id]
                    triplet.update({'tactic': tactic, 'file_name': file_name})
                    del triplet['file_id']
                    triplet = check_triplet(triplet)
                    result.append(triplet)
            except Exception as e:
                result = None
                return None
            
            # finish_reason = response["choices"][0]["finish_reason"]
            # response_time = round(response.response_ms / 1000, 2)
            response_dict = {
                "triplets": result, # list of the triplets
                # "finish_reason": finish_reason,
                # "file_name": file_name,
                # "usage": usage,
                # "time": response_time,
                # "sents": related_sents,
                "tactic": tactic
            }
            return response_dict
        except openai.RateLimitError as e:
            # Rate Limit has been reached : wait and resend
            time.sleep(3)
        except openai.APIConnectionError as e:
            # network is not connected : wait and resend
            time.sleep(1)
        except openai.AuthenticationError as e:
            # please change the api-key
            print(e)
            return None
        except openai.BadRequestError as e:
            print(e)
            return None
        
        except Exception as e:
            print(e)
            return None

def parser_attack_graph_response(response, save_dir, file_id, file_name):
    if response is None:
        return None
    triplets = response['triplets']
    related_sentences = response['sents']
    result = {"events": triplets, "id": file_id, "file_name": file_name, "sentences": related_sentences, "tactic_label": True}
    # save
    try:
        with open(op.join(save_dir, file_name + '.json'), 'w') as f:
            json.dump(result, f)
    except:
        return None
    return result

async def process_files(report_dir, save_dir, file_idxes, file_names):
    # final results
    results = {}
    for name in file_names:
        init_json ={
            'triplets': [],
            'file_name': name,
            'tactic_label': True,
        }
        results.update({name: init_json})
    # requests
    tasks = []
    # {tactic_1 :[{id, name, text}], tactic_2 : []...}
    # collect the same tactic text from multi files
    tactic_bags = {}
    
    for i in range(len(file_names)):
        file_name = file_names[i]
        file_idx = file_idxes[i]
        with open(op.join(report_dir,file_name+'.json'), 'r', encoding='utf-8') as f:
            rewrite_dict = json.load(f)
        if type(rewrite_dict) != dict:
            continue
        results[file_name].update({'rewrite': rewrite_dict}) # add rewrite result for results

        for tactic in rewrite_dict:
            bag = {
                'file_id' : file_idx,
                'file_name': file_name,
                'text': rewrite_dict[tactic]
            }
            if bag['text'] == 'None':
                continue # skip None text in rewrite part
            if bag['text'] == None:
                continue
            if tactic_bags.get(tactic) is None:
                tactic_bags.update({tactic: []})
            tactic_bags[tactic].append(bag)
    for tactic in tactic_bags:
        bags = tactic_bags[tactic]
        args = {'bags': bags, 'tactic': tactic, 'model': current_model}
        tasks.append(async_wrap(request_attack_graph, args))

    response_dicts = await asyncio.gather(*tasks)

    
    # parse responses
    for response_dict in response_dicts:
        if response_dict is None:
            continue
        triplets = response_dict['triplets']
        for triplet in triplets:
            # collect the triplets according to the file name
            file_name = triplet['file_name']
            del triplet['file_name']
            results[file_name]['triplets'].append(triplet)
    
    # sort the triplets according to the tactic order
    for file_name in results:
        triplets = results[file_name]['triplets']
        sorted_triplets = sorted(triplets, key=lambda x: Tactic_label_order[x['tactic']])
        results[file_name]['triplets'] = sorted_triplets

    # save results
    for file_name in results:
        save_path = op.join(save_dir, file_name+'.json')
        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(results[file_name], f, indent=4)
    return results

def check_result_triplets(result_dir):
    for file in os.listdir(result_dir):
        with open(op.join(result_dir, file), 'r', encoding='utf-8') as f:
            result = json.load(f)
        triplets = result['triplets']
        checked_triplets = []
        for t in triplets:
            checked_triplets.append(check_triplet(t))
        result['triplets'] = checked_triplets
        with open(op.join(result_dir, file), 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)
        

def main():
    args = args_parser()
    report_dir = args.report_dir
    save_dir = args.save_dir
    step = args.step
    paths = re.split( r'\\\\|/', report_dir)
    remove_empty = []
    for p in paths:
        if p == '':
            continue
        remove_empty.append(p)
    paths = remove_empty
    root_dir = '/'.join(paths[:-1])
    if save_dir is None:
        save_dir = op.join(root_dir, 'result')
    if not op.exists(save_dir):
        os.makedirs(save_dir)

    if args.check_result:
        check_result_triplets(save_dir)
        return
    #set_openai_key(args.api_key_file)
    # read files
    all_reports_name = [] 
    for file in os.listdir(report_dir):
        if not file.endswith('json'):
            continue
        name = file[:-5] # remove '.json' in the end
        if op.exists(op.join(save_dir, name + '.json')):
            pass
            continue
        all_reports_name.append(name)
    file_idxs = list(range(0, len(all_reports_name)))

    t = time.time()
    all_results = asyncio.run(async_requests(report_dir, save_dir, file_idxs, all_reports_name, step ,current_model))
    # async_requests
    print('actual time = {}s'.format(round(time.time() - t, 2)))

    
async def async_requests(report_dir, save_dir, file_idxes, all_reports_name, step, current_model): 
    # asynchronously requests
    all_results = []
    for i in range(0, len(all_reports_name), step):
        f_names = all_reports_name[i:i+step]
        f_idxes = file_idxes[i:i+step]
        results = await process_files(report_dir, save_dir, f_idxes, f_names)
        results_extend = []
        for res in results:
            if res is None:
                continue
            results_extend.append(res)
        all_results.extend(results_extend)
        print(i)
    return all_results

def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report-dir', '-rd', default='./result_file/1.CTI_Rewrited')
    parser.add_argument('--save-dir', '-sd', default='./result_file/2.CTI_Extractor')
    #parser.add_argument('--api-key-file', '-akf', default='./report_extractor/template_files/api_key.txt')
    parser.add_argument('--step', '-s',type=int, default=5)
    parser.add_argument('--check-result', action='store_true', default=False)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    main()