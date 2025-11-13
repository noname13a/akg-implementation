import os
from os import path as op
import json
import argparse
import copy
import random
import re

#import nltk
#import tiktoken

# universal
def num_tokens_from_string(string: str, model_name: str) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.encoding_for_model(model_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

def message_token_count(message, model='gpt-4-1106-preview'):
    num_token = 0
    for item in message:
        num_token += num_tokens_from_string(item["content"], model)
    return num_token

def save_list2json(input_string: str, save_path: str):
    save_obj = [x.strip() for x in input_string.strip().split(',')]
    
    with open(save_path, 'w') as f:
        json.dump(save_obj, f)

def load_string(description_file_path, addtional_json_file_path=None, json_item_key=None, is_unique=False):
    rule_str = ''
    if not op.exists(description_file_path):
        raise Exception("Rule path {} doesn't exist".format(description_file_path))
    
    with open(description_file_path, 'r', encoding='utf-8') as f:
        rule_str = rule_str + f.read().strip()
    
    if addtional_json_file_path is not None:
        if not op.exists(addtional_json_file_path):
            raise Exception("The json path {} of Rule path {} doesn't exist".format(addtional_json_file_path, description_file_path))
        with open(addtional_json_file_path, 'r') as f:
            jlist = json.load(f)
        if json_item_key is not None:
            jlist = [x[json_item_key] for x in jlist]
        if is_unique:
            jlist = list(set(jlist))
        rule_str = rule_str + ' "{}"'.format(', '.join(jlist))
    return rule_str

def load_txt(txt_file_path):
    output_str = ''
    if not op.exists(txt_file_path):
        raise Exception("Txt file path {} doesn't exist".format(txt_file_path))
    with open(txt_file_path, 'r', encoding='utf-8') as f:
        output_str = f.read()
    return output_str     
# report classifier
report_classifier_dir = './report_extractor/template_files/report_classifier'

def save_report_types_meanings():
    text = '''(1)Strategic Threat Intelligence@Strategic Threat Intelligence is high-level information, consumed at board level or by other senior decision-makers. It is unlikely to be technical and can cover such things as the financial impact of cyber activity, attack trends, and areas that might impact on high-level business decisions. An example would be a report indicating that a particular government is believed to hack into foreign companies who have direct competitors within their own nation, hence a board might consider this fact when weighing up the benefits and risks of entering that competitive marketplace, and to help them allocate effort and budget to mitigate the expected attacks. Strategic threat intelligence is almost exclusively in the form of prose, such as reports, briefings or conversations. 
(2)Operational Threat Intelligence@Operational Threat Intelligenceis information about specific impending attacks against the organisation and is initially consumed by higher-level security staff, such as security managers or heads of incident response. Any organisation would dearly love to have true operational threat intelligence, i.e. to know which groups are going to attack them, when and how – but such intelligence is very rare. In the majority of cases, only a government will have the sort of access to attack groups and their infrastructure necessary to collect this type of intelligence. For nation-state threats, it simply isn’t possible for a private entity to legally gain access to the relevant communication channels and hence good operational threat intelligence won’t be an option for many. There are cases, however,where operational intelligence might be available, such as when an organisation is targeted by more public actors, including hacktivists. It is advisable for organisations to focus on these cases, where details of attacks can be found from open source intelligence or providers with access to closed chat forums. Another form of operational threat intelligence that might be available is that derived from activity-based attacks: where specific activities or events in the real world result in attacks in the cyber domain. In such instances, future attacks can sometimes be predicted following certain events. This linking of attacks to real-world events is common practice in physical security but less commonly seen in cyber security.
(3)Tactical Threat Intelligenceis@Tactical Threat Intelligenceis often referred to as Tactics, Techniques, and Procedures (TTPs) and is information about how threat actors are conducting attacks.Tactical threat intelligence is consumed by defenders and incident responders to ensure that their defences, alerting and investigation are prepared for current tactics. For example, the fact that attackers are using tools (often Mimikatz derivatives) to obtain cleartext credentials and then replaying those credentials through PsExec is tactical intelligence that could prompt defenders to change policy and prevent interactive logins by admins, and to ensure logging will capture the use of PsExec4. Tactical threat intelligence is often gained by reading white papers or the technical press, communicating with peers in other organisations to learn what they’re seeing attackers do, or purchasing from a provider of such intelligence.
(4)Technical Threat Intelligenceis@Technical Threat Intelligenceis information (or, more often, data) that is normally consumed through technical means. An example would be a feed of IP addresses suspected of being malicious or implicated as command and control servers.Technical threat intelligence often has a short lifetime as attackers can easily change IP addresses or modify MD5 sums, hence the need to consume such intelligence automatically. Technical threat intelligence typically feeds the investigative or monitoring functions of a business, by – for example – blocking attempted connections to suspect servers.
'''
    text_list = [x.strip() for x in text.strip().split('\n')]
    type_meaning_pair = {}
    for x in text_list:
        type_name, meaning = tuple([xx.strip() for xx in x.split('@')])
        type_name = re.sub(r'\(\d+\)', '', type_name)
        type_meaning_pair.update({type_name: meaning})
    
    with open(op.join(report_classifier_dir, 'report_type_meanings.json'), 'w') as f:
        json.dump(type_meaning_pair, f)

def load_rule_types(txt_path: str, report_type_meanings_json: dict):
    with open(txt_path, 'r', encoding='utf-8') as f:
        rule_type = f.read().strip()
    rule_type = rule_type + ' "{}"'.format(', '.join(list(report_type_meanings_json.keys())))
    return rule_type

def load_rule_type_meanings(txt_path: str, report_type_meanings_json: dict):
    with open(txt_path, 'r', encoding='utf-8') as f:
        rule_type_meanings = f.read().strip()
    rule_type_meanings = rule_type_meanings + '\n' + '\n'.join(['{}. {}:{}'.format(i+1, type_key, report_type_meanings_json[type_key]) for i, type_key in enumerate(report_type_meanings_json)])
    return rule_type_meanings

# report classifier
def report_classifier_template(request_text, template_path=report_classifier_dir):
    if not op.exists(template_path):
        raise Exception("Report Classifier template directory \"{}\" doesn't exist".format(template_path))
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt'))
    rules = []
    rules.append(load_string(op.join(template_path, 'system_rule_format.txt')))
    with open(op.join(template_path, 'report_type_meanings.json'), 'r') as f:
        report_type_meaing_json = json.load(f)
    rules.append(load_rule_types(op.join(template_path, 'system_rule_type.txt'), report_type_meaing_json))
    rules.append(load_rule_type_meanings(op.join(template_path, 'system_rule_type_meaning.txt'), report_type_meaing_json))
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))

    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": example_request},
        {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages

def report_classifier_using_example():
    ms = report_classifier_template('', report_classifier_dir)
    for m in ms:
        print(m['content'])

# attack graph
attack_graph_dir = './report_extractor/template_files/attack_graph'

# save files
def save_relations():
    relations = "Modify,Construct,Use,Detect,Write,Operate,Has vulnerability,Has geolocation,Belong to,Locate at,Has URL,Has value,Has hostname"
    save_list2json(relations, op.join(attack_graph_dir, 'relations.json'))
    with open(op.join(attack_graph_dir, 'relations.json'), 'r') as f:
        r_list = json.load(f)
    print(r_list)

def save_entities():
    entities = "Report Type,Author,Vender,Date,Infrastrcucture,Location,Malware,Organization,Security Tool,Vulnerablity,Vulnerable Software,System,Platform,Threat Actor,Tactic,Technique,Filename,Filepath,URL,Registy,Domain,Hash,IP"

    save_list2json(entities, op.join(attack_graph_dir, 'entities.json'))
    with open(op.join(attack_graph_dir, 'entities.json'), 'r') as f:
        r_list = json.load(f)
    print(r_list)

# attack graph template
def attack_graph_template(request_text, template_path=attack_graph_dir):
    if not op.exists(template_path):
        raise Exception("Attack Graph template directory \"{}\" doesn't exist".format(template_path))
    with open(op.join(template_path, 'output_format copy.json')) as f:
        output_format = json.load(f)
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt'))

    rules = []
    rules.append(load_string(op.join(template_path, 'system_rule_format.txt')))
    # rules.append(load_rule2string(op.join(template_path, 'system_rule_infinitive.txt')))
    # rules.append(load_rule2string(op.join(template_path, 'system_rule_no_passive.txt')))
    # rules.append(load_rule2string(op.join(template_path, 'system_rule_sent_num.txt')))
    # rules.append(load_rule2string(op.join(template_path, 'system_rule_num_output.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_entities.txt'), op.join(template_path, 'entities.json'), 'name'))
    rules.append(load_string(op.join(template_path, 'system_rule_relation.txt'), op.join(template_path, 'relations.json'), 'name', True))
    rules.append(load_string(op.join(template_path, 'system_rule_no_pronouns.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_relation_form.txt')))
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]

    demonstrations = []
    demonstrations.append(load_string(op.join(template_path, 'demonstration_1.txt')))
    # add 'Demonstration n:'
    demonstrations = ['Demonstration {}: {}'.format(i+1, demo) for i, demo in enumerate(demonstrations)]
    system_content = system_background + '\n' + '\n'.join(rules) + '\n' + '\n'.join(demonstrations)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))

    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        # {"role": "user", "content": example_request},
        # {"role": "assistant", "content": example_response},
        {"role": "user", "content": "Please extract the  please extract the security triplets in the artciles below:\n{}\nExtracted triplets are:".format(request_text)}
    ]
    return messages, output_format

# using example
def attack_graph_using_example():
    ms, tools = attack_graph_template('', attack_graph_dir)
    for m in ms:
        print(m['content'])

# TTP label
mitre_json_path = './preprocessing/TTPScraping/mitre.json'

# tactic
mitre_tactic_dir = './report_extractor/template_files/mitre_tactic'

def tactic_candidate_rule(tactics):
    cand_rule = 'Please label the sentences in the given text with the tactic-level candidate tags. If some sentences in the text may not belong to any of the candidate tags, please skip them and do not add the sentences number of them to your response. The candidate tags are as follows:'
    cand_tactics = []
    for tact in tactics:
        cand_tactics.append(tact['name'])
    cand_rule =  cand_rule + ' "{}"'.format(', '.join(cand_tactics))
    return cand_rule

def tactic_candidate_meaning_rule(tactics):
    cand_rule = 'The meaning of the candidate tags is as follows:\n'
    cand_tactic_meanings = []
    for i, tact in enumerate(tactics):
        cand_tactic_meanings.append('{}. {}:{}'.format(i+1, tact['name'], tact['description']))
    cand_rule =  cand_rule + '\n'.join(cand_tactic_meanings)
    return cand_rule

# tactic template
def mitre_tactic_label_template(request_text, mitre, template_path=mitre_tactic_dir):
    if not op.exists(template_path):
        raise Exception("MITRE Tactic template directory \"{}\" doesn't exist".format(template_path))
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    tactics = mitre['tactics']
    rules.append(tactic_candidate_rule(tactics))
    rules.append(tactic_candidate_meaning_rule(tactics))
    rules.append(load_string(op.join(template_path, 'system_rule_sent_num.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_num_output.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_format.txt')))
    
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))

    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": example_request},
        {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages

# using example
def tactic_using_example():
    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)
    ms = mitre_tactic_label_template('your input article', mitre, mitre_tactic_dir)
    for m in ms:
        print(m['content'])

# technique
mitre_technique_dir = './report_extractor/template_files/mitre_technique'

def technique_candidate_rule(techniques):
    cand_rule = 'Please label the sentences in the given text with the technique-level candidate tags. If some sentences in the text may not belong to any of the candidate tags, please skip them and do not add the sentences number of them to your response. The candidate tags are as follows:'
    cand_techs = []
    for tech in techniques:
        cand_techs.append('{}-{}'.format(tech['id'], tech['name']))
    cand_rule = cand_rule + ' "{}"'.format(', '.join(cand_techs))
    return cand_rule

def technique_candidate_meaning_rule(techniques, is_detailed_description=False):
    cand_rule = 'The meaning of the candidate tags is as follows:\n'
    cand_tech_meanings = []
    for i, tech in enumerate(techniques):
        cand_tech_meanings.append('{}. {}-{}:{}'.format(
            i+1,
            tech['id'],
            tech['name'],
            tech['detailed_description'] if is_detailed_description else tech['description']))
    cand_rule = cand_rule + '\n'.join(cand_tech_meanings)
    return cand_rule
        
# technique template
def mitre_technique_label_template(request_text, mitre, parent_labels: dict, template_path=mitre_technique_dir, max_neg_num=5):
    # parent_labels : {'tactic': ''}
    parent_tactic = parent_labels.get('tactic')
    if parent_tactic is None:
        raise Exception("Tactic is not found in input params: parent_label, please input the parent_label as {'tactic': 'name of parent tact'}")
    if parent_tactic == 'Others':
        return None, None
    if not op.exists(template_path):
        raise Exception("MITRE Technique template directory \"{}\" doesn't exist".format(template_path))
    with open(op.join(template_path, 'output_format.json')) as f:
        output_format = json.load(f)
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    techniques = None
    for tact in mitre['tactics']:
        if tact['name'] == parent_tactic:
            techniques = tact['techniques']
            break
    if techniques is None:
        raise Exception("Tactic {} is not in MITRE".format(parent_tactic))
    
    rules.append(technique_candidate_rule(techniques))
    rules.append(technique_candidate_meaning_rule(techniques))
    rules.append(load_string(op.join(template_path, 'system_rule_sent_num.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_num_output.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_format.txt')))
    
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # example generate
    examples = []
    for tech in techniques:
        if len(tech['examples']) ==0 :
            continue
        # select the first example as the prompt example
        sents = nltk.sent_tokenize(tech['examples'][0]['description']) # split the example paragraph into sents
        tag = '{}-{}'.format(tech['id'], tech['name'])
        for sent in sents:
            examples.append({'tag': tag, 'text': sent})
    # add negative examples
    '''with open(op.join(template_path, 'negative_samples.txt'), 'r', encoding='utf-8') as f:
        text = f.read().strip()
    neg_sents = text.split('\n')
    random.shuffle(neg_sents)
    for neg_sent in neg_sents[:max_neg_num]:
        examples.append({'tag': '', 'text': neg_sent})'''
    
    random.shuffle(examples) # shuffle examples

    request_lines = []
    response_dict = {}
    response_lines = []
    for i, ex in enumerate(examples):
        request_lines.append('{}: {}'.format(i, ex['text']))
        if ex['tag'] == '':
            continue
        if response_dict.get(ex['tag']) is None:
            response_dict.update({ex['tag']: [i]})
        else:
            response_dict[ex['tag']].append(i)
    for tech in techniques:
        tag = '{}-{}'.format(tech['id'], tech['name'])
        if response_dict.get(tag) is None:
            response_lines.append('{}:()'.format(tag))
        else:
            response_lines.append('{}:({})'.format(tag, ','.join([str(i) for i in response_dict[tag]])))
    # add example request
    example_request = 'This is an example of content types label,given article as follows:\n'
    example_request = example_request + '\n'.join(request_lines)

    # add example response
    example_response = ''
    example_response = example_response + '\n'.join(response_lines)

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": example_request},
        {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages, output_format

def technique_using_example():
    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)
    tactic = random.choice(mitre['tactics'])
    parent_dict = {'tactic': tactic['name']}
    # parent_dict = {'tactic': 'Reconnaissance'}
    ms, of = mitre_technique_label_template('your input article', mitre, parent_dict, mitre_technique_dir, 5)
    for m in ms:
        print(m['content'])
    
# sub technique
mitre_sub_technique_dir = './report_extractor/template_files/mitre_sub_technique'
    
def sub_technique_candidate_rule(sub_techniques):
    cand_rule = 'Please label the sentences in the given text with the sub-technique-level candidate tags. If some sentences in the text may not belong to any of the candidate tags, please skip them and do not add the sentences number of them to your response. The candidate tags are as follows:'
    cand_sub_techs = []
    for sub_tech in sub_techniques:
        cand_sub_techs.append('{}-{}'.format(sub_tech['id'], sub_tech['name']))
    cand_rule = cand_rule + ' "{}"'.format(', '.join(cand_sub_techs))
    return cand_rule

def sub_technique_candidate_meaning_rule(sub_techniques, is_detailed_description=False):
    cand_rule = 'The meaning of the candidate tags is as follows:\n'
    cand_sub_tech_meanings = []
    for i, sub_tech in enumerate(sub_techniques):
        cand_sub_tech_meanings.append('{}. {}-{}:{}'.format(
            i+1,
            sub_tech['id'],
            sub_tech['name'],
            sub_tech['detailed_description'] if is_detailed_description else sub_tech['description']))
    cand_rule = cand_rule + '\n'.join(cand_sub_tech_meanings)
    return cand_rule

# technique template
def mitre_sub_technique_label_template(request_text, mitre, parent_labels: dict, template_path=mitre_sub_technique_dir, max_neg_num=5):
    # need validation of existence of sub technniques for given technique
    # return None if not valid
    # parent_labels : {'tactic': '', 'technique': ''}
    parent_tactic = parent_labels.get('tactic')
    parent_technique = parent_labels.get('technique')
    if parent_tactic is None:
        raise Exception("Tactic is not found in input params: parent_label, please input the parent_label as {'tactic': 'name of parent tact', 'technique': 'name of parent tech'}")
    if parent_technique is None:
        raise Exception("Techinque is not found in input params: parent_label, please input the parent_label as {'tactic': 'name of parent tact', 'technique': 'name of parent tech'}")
    if parent_tactic == 'Others':
        return None
    if parent_technique == 'Others':
        return None
    if not op.exists(template_path):
        raise Exception("MITRE Sub Technique template directory \"{}\" doesn't exist".format(template_path))
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    techniques = None
    for tact in mitre['tactics']:
        if tact['name'] == parent_tactic:
            techniques = tact['techniques']
            break
    if techniques is None:
        raise Exception("Tactic {} is not in MITRE".format(parent_tactic))
    
    sub_techniques = None
    for tech in techniques:
        if tech['name'] == parent_technique:
            sub_techniques = tech['sub_techniques']
            break
    if sub_techniques is None:
        raise Exception("Technique {} is not in the category of Tactic {}".format(parent_technique, parent_tactic))
    if len(sub_techniques) == 0:
        # return None if no sub tech candidates are valid
        return None
    
    rules.append(sub_technique_candidate_rule(sub_techniques))
    rules.append(sub_technique_candidate_meaning_rule(sub_techniques))
    rules.append(load_string(op.join(template_path, 'system_rule_sent_num.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_num_output.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_format.txt')))
    
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # example generate
    examples = []
    for sub_tech in sub_techniques:
        if len(sub_tech['examples']) ==0 :
            continue
        # select the first example as the prompt example
        sents = nltk.sent_tokenize(sub_tech['examples'][0]['description']) # split the example paragraph into sents
        tag = '{}-{}'.format(sub_tech['id'], sub_tech['name'])
        for sent in sents:
            examples.append({'tag': tag, 'text': sent})
    # add negative examples
    '''with open(op.join(template_path, 'negative_samples.txt'), 'r', encoding='utf-8') as f:
        text = f.read().strip()
    neg_sents = text.split('\n')
    random.shuffle(neg_sents)
    for neg_sent in neg_sents[:max_neg_num]:
        examples.append({'tag': '', 'text': neg_sent})'''
    
    random.shuffle(examples) # shuffle examples

    request_lines = []
    response_dict = {}
    response_lines = []
    for i, ex in enumerate(examples):
        request_lines.append('{}: {}'.format(i, ex['text']))
        if ex['tag'] == '':
            continue
        if response_dict.get(ex['tag']) is None:
            response_dict.update({ex['tag']: [i]})
        else:
            response_dict[ex['tag']].append(i)
    for sub_tech in sub_techniques:
        tag = '{}-{}'.format(sub_tech['id'], sub_tech['name'])
        if response_dict.get(tag) is None:
            response_lines.append('{}:()'.format(tag))
        else:
            response_lines.append('{}:({})'.format(tag, ','.join([str(i) for i in response_dict[tag]])))
    # add example request
    example_request = 'This is an example of content types label,given article as follows:\n'
    example_request = example_request + '\n'.join(request_lines)

    # add example response
    example_response = ''
    example_response = example_response + '\n'.join(response_lines)

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": example_request},
        {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages

def sub_technique_using_example():
    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)
    tactic = random.choice(mitre['tactics'])
    technique = random.choice(tactic['techniques'])
    parent_dict = {'tactic': tactic['name'], 'technique': technique['name']}
    # parent_dict = {'tactic': 'Reconnaissance', 'technique': 'Gather Victim Host Information'}
    ms = mitre_sub_technique_label_template('your input article', mitre, parent_dict, mitre_sub_technique_dir, 5)
    if ms is not None:
        for m in ms:
            print(m['content'])
    else:
        print('No sub-techniques found in tactic {} technique {}'.format(parent_dict['tactic'], parent_dict['technique']))
    print(parent_dict)

# stage state pool summarization
stage_state_pool_dir = './report_extractor/template_files/stage_state_pool_summarization'

def save_state_pool():
    with open(op.join(stage_state_pool_dir, 'stage_state_pool_description.txt'), 'r', encoding='utf-8') as f:
        text = f.read().strip()
    lines = text.split('\n')
    state_pool_des = {}
    for line in lines:
        strs = line.strip().split(':')
        state_pool_des.update({strs[0].strip(): strs[1].strip()})
    with open(op.join(stage_state_pool_dir, 'stage_state_pool_description.json'), 'w') as f:
        json.dump(state_pool_des, f)

def state_rule(state_pool_des: dict):
    rule = 'The extraction content includes five categories:'
    state_list = list(state_pool_des.keys())
    rule = rule + ' "{}"'.format(', '.join(state_list))
    return rule

def state_meaning_rule(state_pool_des: dict):
    rule = 'The meanings of the five categories are as follows:\n'
    des_list = []
    for i, state in enumerate(state_pool_des):
        des_list.append('{}. {}:{}'.format(i+1, state, state_pool_des[state]))
    rule = rule + '\n'.join(des_list)
    return rule

def stage_state_pool_summarization_template(request_text, state_pool_des, template_path=stage_state_pool_dir):
    if not op.exists(template_path):
        raise Exception("Stage State Pool Summarization template directory \"{}\" doesn't exist".format(template_path))
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    
    rules.append(state_rule(state_pool_des))
    rules.append(state_meaning_rule(state_pool_des))
    rules.append(load_txt(op.join(template_path, 'system_rule_format.txt')))
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    demonstrations = []
    demonstrations.append(load_string(op.join(template_path, 'demonstration_1.txt')))
    # add 'Demonstration n:'
    demonstrations = ['Demonstration {}: {}'.format(i+1, demo) for i, demo in enumerate(demonstrations)]
    system_content = system_background + '\n' + '\n'.join(rules) + '\n' + '\n'.join(demonstrations)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))

    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        # {"role": "user", "content": example_request},
        # {"role": "assistant", "content": example_response},
        {"role": "user", "content": "Please summarize the article below:\n{}\nThe summary is:".format(request_text)}
    ]
    return messages

def stage_state_pool_summarization_using_example():
    with open(op.join(stage_state_pool_dir, 'stage_state_pool_description.json')) as f:
        state_pool_des = json.load(f)
    ms = stage_state_pool_summarization_template('your input article', state_pool_des, stage_state_pool_dir)
    for m in ms:
        print(m['content'])
    

# rewrite and extract
rewrite_dir = './aux_files/templates_rewriter'
Tactic_label_order = {
    'Reconnaissance': 0,
    'Resource Development': 1,
    'Initial Access': 2,
    'Execution': 3,
    'Persistence': 4,
    'Privilege Escalation': 5,
    'Defense Evasion': 6,
    'Credential Access': 7,
    'Discovery': 8,
    'Lateral Movement': 9,
    'Collection': 10,
    'Command and Control': 11,
    'Exfiltration': 12,
    'Impact': 13,
    'Others': 14
}

def mitre_tactic_technique_description(tactics):
    rule_description = 'There are 14 tactics in cyber attacks, and these 14 tactics will be provided, along with their names and corresponding descriptions, in the logic order of cyber attack:'
    tactic_description = []
    for tact in tactics:
        tactic_description.append(tact)
    tactic_description = sorted(tactic_description, key=lambda x: Tactic_label_order[x['name']])
    tactic_technique_meanings = []
    for i, tact in enumerate(tactic_description):
        tactic_technique_meanings.append('{}. {}:{}'.format(i+1, tact['name'], tact['description']))
        for j, tech in enumerate(tact['techniques']):
            tactic_technique_meanings.append('{}.{} {}'.format(i+1, j+1, tech['name']))
    rule_description =  rule_description + '\n'.join(tactic_technique_meanings)
    return rule_description

def rewriting_template(request_text, mitre, template_path=rewrite_dir):
    if not op.exists(template_path):
        raise Exception("Rewrite template directory \"{}\" doesn't exist".format(template_path))
    with open(op.join(template_path, 'output_format.json')) as f:
        output_format = json.load(f)
    # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    tactics = mitre['tactics']
    rules.append(load_string(op.join(template_path, 'system_rule_rewrite.txt')))
    rules.append(mitre_tactic_technique_description(tactics))
    rules.append(load_string(op.join(template_path, 'system_rule_entities.txt'), op.join(template_path, 'entities.json'), 'name'))
    rules.append(load_string(op.join(template_path, 'system_rule_relation.txt'), op.join(template_path, 'relations.json'), 'name', True))
    rules.append(load_string(op.join(template_path, 'system_rule_Others.txt')))
    # rules.append(load_rule2string(op.join(template_path, 'systen_rule_narrative_sequence.txt')))
        
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))
    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        # {"role": "user", "content": example_request},
        # {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages, output_format

def rewriting_using_example():
    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)
    ms, tools = rewriting_template('your input article', mitre, rewrite_dir)
    for m in ms:
        print(m['content'])
    print(message_token_count(ms, model='gpt-3.5-turbo-1106'))


# labeled text
label_entities_dir = './report_extractor/template_files/labeled_text'

def labeled_text_template(request_text, template_path=label_entities_dir):
    if not op.exists(template_path):
        raise Exception("Label entities in text template directory \"{}\" doesn't exist".format(template_path))
    with open(op.join(template_path, 'output_format.json')) as f:
        output_format = json.load(f)
     # add system
    system_content = ''
    system_background = load_txt(op.join(template_path, 'system_role_description.txt')).strip()
    rules = []
    rules.append(load_string(op.join(template_path, 'system_rule_add_label.txt')))
    rules.append(load_string(op.join(template_path, 'system_rule_text_unchanged.txt')))
        
    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)
    
    # add example request
    example_request = load_txt(op.join(template_path, 'example_request_1.txt'))

    # add example response
    example_response = load_txt(op.join(template_path, 'example_response_1.txt'))

    messages = [
        {"role": "system", "content": system_content},
        # {"role": "user", "content": example_request},
        # {"role": "assistant", "content": example_response},
        {"role": "user", "content": "article:\n{}".format(request_text)}
    ]
    return messages, output_format

def add_description_templete(numbered_triplets, numbered_texts, schema_path, parent_labels, model):
    
    # 参数存在性判断：request_text，schema_path
    if numbered_triplets is None or numbered_texts is None:
        return None, None
    if not op.exists(schema_path):
        raise Exception("Scheam directory \"{}\" doesn't exist".format(schema_path))
    
    # tool_use格式规定：读取decription输出格式,这里需要自己撰写一个输出格式文件
    with open(op.join(schema_path, 'output_format_description.json')) as f:
        output_format = json.load(f)



    # add system，添加系统背景信息
    system_content = ''
    system_background = load_txt(op.join(schema_path, 'system_role_description.txt')).strip()
    rules = []

    rules.append(load_string(op.join(schema_path, 'system_rule_1.txt')))
    rules.append(load_string(op.join(schema_path, 'system_rule_2.txt')))
    rules.append(load_string(op.join(schema_path, 'system_rule_3.txt')))

    # add 'Rule n:'
    rules = ['Rule {}: {}'.format(i+1, rule) for i, rule in enumerate(rules)]
    system_content = system_background + '\n' + '\n'.join(rules)

    # add example，添加示例信息
    demonstrations = []
    demonstrations.append(load_string(op.join(schema_path, 'demonstraction.txt')))

    demonstration_text = '\n'.join(demonstrations)

    query = "The reference texts as follows:\n{}\nThe triplets as follows:\n{}\n The triplets for adding entity and relation specific explanations are as follows:\n".format(numbered_texts, numbered_triplets)

    prompt_sys = '\n'.join([system_content, demonstration_text])

    #print(query)

    #print(prompt_sys)

    messages = [
            {"role": "system", "content": prompt_sys},
            {'role': "user", "content": query}
        ]

    return messages, output_format

if __name__ == '__main__':
    # attack_graph_using_example()
    # tactic_using_example()
    # technique_using_example()
    # sub_technique_using_example()
    stage_state_pool_summarization_using_example()
    # report_classifier_using_example()
    # rewriting_using_example()
    


    