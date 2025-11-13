import os
from os import path as op
import json
import re
import random

import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network


from nltk.stem import WordNetLemmatizer
from nltk import word_tokenize, pos_tag
from nltk.corpus import wordnet


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


def get_wordnet_pos(tag):
    if tag.startswith('J'):
        return wordnet.ADJ
    elif tag.startswith('V'):
        return wordnet.VERB
    elif tag.startswith('N'):
        return wordnet.NOUN
    elif tag.startswith('R'):
        return wordnet.ADV
    else:
        return None

def lemmatize(s:str):
    tokens = word_tokenize(s) # tokenization"
    tagged_sent = pos_tag(tokens) # part-of-speech tagging
    wnl = WordNetLemmatizer()
    lemmas = []
    for tag in tagged_sent:
        wordnet_pos = get_wordnet_pos(tag[1]) or wordnet.NOUN
        lemmas.append(wnl.lemmatize(tag[0], pos=wordnet_pos))
    result = ' '.join(lemmas)
    return result

def filtering(x:str, filter_type='e', lemmatization=False):
        x = x.lower()
        e_filter_map = {
            r'^[Tt]he': '',
            '-': ' ',
            r'c2 server[s]?': 'c & c server',
            r'command and control server[s]?': 'c & c server', 
            r'threat actor[s]?': 'attacker',
            r'adversary': 'attacker',
            r'adversaries': 'attacker',
            r'a c & c server': 'c & c server'
            
        }
        r_filter_map = {
            '-': ' ',
        }
        
        
        if filter_type == 'r':
            filter_map = r_filter_map
        else:
            filter_map = e_filter_map

        for p in filter_map:
            x = re.sub(p, filter_map[p], x).strip()

        if lemmatization == True:
            x = lemmatize(x)

        # x = x.title()
        if x == '':
            return 'None'
        return x

def get_networkx(json_dict, size_multipler=1.0):
    # Greate a empty graph
    G = nx.DiGraph()

    # event node
    event_list = ["assess", "bypass", "browse", "choose", "click", "complete", "collect", "connect", "copy", "decode", "deploy", "encode", "enter", "escalate", "initate", "exploit", "extract", "fetch", "gain", "gather", "lanch", "leave", "load", "modify", "obtain", "open", "select", "send", "simulate", "start", "steal", "trigger", "use", "write", "read", "communicate with", "communicate", "execute", "exfiltrate to", 'contain', 'install', 'compromise', 'deliver', 'execute on', 'establish', 'utilize', 'observe', 'download', 'create', 'detect', 'make', 'maintain', 'exfiltrate', 'attempt']
    event_idx = 0
    tactic_offset = 1000
    sentence_num_event_dict = {} # used for temporary links among events
    TTP_labels = {}
    for obj in json_dict['triplets']:
        if filtering(obj['Relation'], 'r', True) in event_list:
            # add event to temporal sequence (defined the by the position it extracted(for now))
            # pos = round(sum(obj['SentenceNums']) / len(obj['SentenceNums']), 1)
            tact = obj['tactic']
            techs = obj['technique']
            if tact == 'Others': 
                continue # skip Ohters tactic
            # tech = obj['tactic']+ '-' +obj['technique'][0]
            # tech_caption = 'Others' if obj['technique'][0] =='Others' else re.search(r'T\d+', obj['technique'][0]).group()
            pos =obj['SentenceNums'][0]+ tactic_offset * Tactic_label_order[tact]
            # assign event with a unique event_idx
            event_with_idx = filtering(obj['Relation'], 'r', True)+'_'+str(event_idx)
            event_idx += 1 # update idx after assigning 
            if sentence_num_event_dict.get(pos) is None:
                sentence_num_event_dict.update({pos: [event_with_idx]})
            else:
                sentence_num_event_dict[pos].append(event_with_idx)
            
            # Entities
            subject = filtering(obj['Subject'], 'e')
            object = filtering(obj['Object'], 'e')

            # add to TTP_labels
            if TTP_labels.get(tact) is None:
                TTP_labels.update({tact: {'techs':{}, 'idx': 0}})
            for te in techs:
                tech =  obj['tactic']+ '-' +te
                TTP_labels[tact]['techs'].update({tech: {'idx': 0}})
            # add event to Graph
            G.add_node(event_with_idx, type='event', tactic=obj['tactic'], technique=tech, sent_nums=obj['SentenceNums'])
            G.add_node(subject, type='entity')
            G.add_node(object, type='entity')
            G.add_edge(subject, event_with_idx, relation='Subject')
            G.add_edge(event_with_idx, object, relation='Object')
            # add tact and tech nodes
            for te in techs:
                tech =  obj['tactic']+ '-' + te
                tech_caption = 'Others' if te =='Others' else re.search(r'T\d+', obj['technique'][0]).group()
                G.add_node(tact, type='tactic')
                G.add_node(tech, type='technique', caption=tech_caption)
                G.add_edge(tact, tech)
                G.add_edge(tech, event_with_idx)
            
        else:
            # Entities
            subject = filtering(obj['Subject'], 'e')
            object = filtering(obj['Object'], 'e')

            # add relation to Graph
            G.add_node(subject, type='entity')
            G.add_node(object, type='entity')
            G.add_edge(subject, object, relation=obj['Relation'], label=obj['Relation'], dashline=True)
    
    # add temporal links among events
    sorted_sentence_num_event_dict = dict(sorted(sentence_num_event_dict.items(), key=lambda x: x[0]))
    keys = list(sorted_sentence_num_event_dict.keys())
    for i in range(len(keys)-1):
        for before_event in sorted_sentence_num_event_dict[keys[i]]:
            for after_event in sorted_sentence_num_event_dict[keys[i+1]]:
                G.add_edge(before_event, after_event)
    
    # assign positions
    pos = {}
    outside_length = [] # length of between the most outside event nodes and x-axis 
    # some params
    base_vertical = 80 * size_multipler
    base_horizontal = 1800 / len(sorted_sentence_num_event_dict.keys()) * size_multipler
    reassign_horizontal = base_horizontal / 2
    vertical_margin = 20 * size_multipler # margin between event and enitities 
    # put event nodes in a sequential manner
    for (i, key_num) in enumerate(sorted_sentence_num_event_dict.keys()):
        nodes = sorted_sentence_num_event_dict[key_num]
        outside_length.append((len(nodes) - 1)/2 * base_vertical )
        for (j, n) in enumerate(nodes):
            x = i * base_horizontal
            y = ((len(nodes) - 1)/2 - j) * base_vertical 
            pos.update({n: (x, y)})
    outside_length_max = max(outside_length)

    # caculate entity nodes
    pos2nodes = {} # reassign nodes if they are assigned to the same position
    visited = {}
    nodes = {}
    for n, attr in G.nodes.data():
        visited.update({n : False})
        nodes.update({n: attr})
    # add event nodes into queue
    queue = []
    for n in G.nodes:
        if nodes[n]['type'] == 'event':
            queue.append(n)
            nodes[n].update({'depth': 0}) # add depth
            visited[n] = True

    while len(queue) > 0:
        head_node = queue.pop(0)
        depth = nodes[head_node]['depth']
        # add neighbour to queue
        neighbour = [n for n in G.predecessors(head_node)] + [n for n in G.successors(head_node)]
        for n in neighbour:
            if not visited[n]:
                queue.append(n)
                nodes[n].update({'depth': depth + 1})
                visited[n] = True 
        # calculate position for entity
        if nodes[head_node]['type'] == 'entity':
            pos_pre = [pos[node] for node in G.predecessors(head_node) if pos.get(node) is not None]
            pos_suc = [pos[node] for node in G.successors(head_node) if pos.get(node) is not None]
            pos_nei = pos_pre + pos_suc            
            x = sum([p[0] for p in pos_nei]) / len(pos_nei)
            y = max([p[1] for p in pos_nei] + [outside_length_max + vertical_margin]) + base_vertical
            # update pos for temporal use
            if head_node == 'apt41':
                # moonbounce vis tricks
                x = x - base_horizontal
            pos.update({head_node: (x, y)})
            if head_node == 'apt41':
                # moonbounce vis tricks
                x = x - base_horizontal
            if pos2nodes.get((x, y)) is None:               
                pos2nodes.update({(x, y): [head_node]})
            else:
                pos2nodes[(x, y)].append(head_node)
    # add tact and tech idx
    sorted_TTP_labels = {tact: TTP_labels[tact] for tact in sorted(TTP_labels, key=lambda t: Tactic_label_order[t])}
    count = 0
    for tact in sorted_TTP_labels:
        tact_tech_idxs = []
        techs = {}
        Others = None
        for tech in sorted_TTP_labels[tact]['techs']:
            tech_dict = {tech: sorted_TTP_labels[tact]['techs'][tech]}
            if tech != 'Others':
                techs.update(tech_dict)
            else:
                Others = tech_dict
        techs = {tech: sorted_TTP_labels[tact]['techs'][tech] for tech in sorted(techs)}
        if Others is not None:
            techs.update(Others)
        for tech in techs:
            tech_dict = techs[tech]
            tech_dict['idx'] = count
            tact_tech_idxs.append(count)
            count += 1
        sorted_TTP_labels[tact]['idx'] = sum(tact_tech_idxs) / len(tact_tech_idxs)
        sorted_TTP_labels[tact]['techs'] = techs
    total_horizontal = max(base_horizontal * (len(sorted_sentence_num_event_dict)-1), 0)
    tech_horizontal_base = total_horizontal / (count - 1)
    TTP_base_vertical = base_vertical * 0.8
    # add tact tech pos
    for tact in sorted_TTP_labels:
        x = tech_horizontal_base * sorted_TTP_labels[tact]['idx']
        y = outside_length_max + TTP_base_vertical * 2
        y = -1 * y
        pos.update({tact: (x, y)})
        for tech in sorted_TTP_labels[tact]['techs']:
            tech_dict = sorted_TTP_labels[tact]['techs'][tech]
            x = tech_horizontal_base * tech_dict['idx']
            y = outside_length_max + TTP_base_vertical
            y = -1 * y
            pos.update({tech: (x,y)})
    # reassign the position for entity nodes
    for p in pos2nodes:
        n_l = pos2nodes[p]
        n_l_positive = [] # put the y of predecessors > 0 in the front
        n_l_negtive = [] # n_l = positive + negtive

        for n in n_l:
            pre_n = [nn for nn in G.predecessors(n)]
            suc_n = [nn for nn in G.successors(n) ]
            nei_n = pre_n + suc_n
            nei_pos = 0
            nei_neg = 0
            for nn in nei_n:
                if pos[nn][1] >= 0:
                    nei_pos += 1
                else:
                    nei_neg += 1
            if nei_pos >= nei_neg:
                n_l_positive.append(n)
            else:
                n_l_negtive.append(n)
        
        up_nodes = []
        down_nodes = []
        # put all nodes to down_nodes
        for i in range(len(n_l)):
            if i <= int((len(n_l)-1) / 2):
                up_nodes.append(n_l[i]) # replace down_nodes with up_nodes for tact and tech vis
            else:
                up_nodes.append(n_l[i])
        if random.randint(0, 1) == 2: # dont exchange
            # exchange for 50% probability
            t = up_nodes
            up_nodes = down_nodes
            down_nodes = t

        for i, n in enumerate(up_nodes):
            x = ((len(up_nodes) - 1) / 2 - i) * reassign_horizontal + p[0]
            y = p[1]
            pos.update({n: (x, y)})
        
        for i, n in enumerate(down_nodes):
            x = ((len(down_nodes) - 1) / 2 - i) * reassign_horizontal + p[0]
            y = -1 * p[1]
            pos.update({n: (x, y)})     

    remove_ns = []
    for n in G.nodes:
        if pos.get(n) is None:
            remove_ns.append(n)
    for n in remove_ns:
        G.remove_node(n)

    # return Graph and pos
    return {'graph': G, 'pos': pos}
            

def draw_matplotlib():
    pass

def draw_pyvis(nx_graph, pos, pic_dir='./', pic_name='nx.html', xpx=800, ypx=1200, size_multipler=1.0):
    nt = Network('{}px'.format(xpx), '{}px'.format(ypx), notebook=True, directed=True)
    
    nt.from_nx(nx_graph)
    
    # set color and shape
    # set inital pos for every nodes
    for n in nt.nodes:
        if pos.get(n['id']) is not None:
            n['x'] = pos[n['id']][0]
            n['y'] = pos[n['id']][1]
        if n['type'] == 'event':
            event_type = n['label'].split('_')[0]
            tactic = n['tactic']
            technique = n['technique']
            nums = [str(i) for i in n['sent_nums']]
            n['label'] = event_type # '\n'.join([event_type, ' '.join(nums)])
            n['shape'] = 'triangle'
            n['color'] = '#8DF56E'
        elif n['type'] == 'tactic':
            n['label'] = n['label']
            n['shape'] = 'box'
            n['color'] = '#FF6347'
        elif n['type'] == 'technique':
            n['label'] = n['caption']
            n['shape'] = 'box'
            n['color'] = '#FFD700'
        elif n['type'] == 'entity':
            successors = list(nx_graph.successors(n['id']))
            if len(successors) > 0:
                n['color'] = '#B4B4D5'
            else:
                n['color'] = '#287271'
        n['size'] = 14 * size_multipler
        n['font'] = {'size': 20 * size_multipler}
        
        # print(n['font_size'])
    
    for e in nt.edges:
        if "label" in e:
            e["font"]={"size": 16 * size_multipler}
        if "dashline" in e:
            e['dashes'] = True        
    nt.show_buttons()
    nt.toggle_physics(False)
    # nt.set_edge_smooth('dynamic')
    nt.show(op.join(pic_dir, pic_name))
    

def draw_one_pic(json_dir, name, save_dir = './graphs'):
    file = f'{name}.json'
    name = file[:-5] # remove '.json'
    with open(op.join(json_dir, file), 'r', encoding='utf-8') as f:
        data_dict = json.load(f)
    size_multipler = 1.0
    try:
        graph_data = get_networkx(data_dict, size_multipler=size_multipler)
        draw_pyvis(graph_data['graph'], graph_data['pos'], pic_dir=save_dir, pic_name=name+'.html', xpx=1200, ypx=1800, size_multipler=size_multipler)
    except Exception as e:
        print('Exception:')
        print(e)
    # gpt_draw(nx_graph)
    
def draw_pics():
    json_dir = op.join('visualization', 'vis_cache')
    save_dir = './graphs'
    if not op.exists(save_dir):
        os.makedirs(save_dir)
    for file in os.listdir(json_dir):
        name = file[:-5] # remove '.json'
        with open(op.join(json_dir, file), 'r', encoding='utf-8') as f:
            data_dict = json.load(f)
        size_multipler = 1.0
        try:
            graph_data = get_networkx(data_dict, size_multipler=size_multipler)
            draw_pyvis(graph_data['graph'], graph_data['pos'], pic_dir=save_dir, pic_name=name+'.html', xpx=1200, ypx=1800, size_multipler=size_multipler)
        except Exception as e:
            print('Exception:')
            print(e)
            pass

if __name__ == '__main__':
    draw_one_pic('visualization', 'C5_APT_SKHack')
    