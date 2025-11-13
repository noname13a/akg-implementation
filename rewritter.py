import openai
import json
from template import rewriting_template
import time

def request_rewriting(extracted_path, mitre , file_name, client, model, temperature=0, max_token=120000, json_count_repeat=1):
    with open(extracted_path, 'r', encoding='utf-8') as f:
        text = f.read()
    messages, tools = rewriting_template(text, mitre)
    tool_choice = {
        "type": "function",
        "function": {
            "name": tools[0]['function']['name']
        }
    }
    count = 0
    while True:
        try:
            response = None
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools = tools,
                tool_choice= tool_choice,
                temperature=temperature,
            )
            # result = response["choices"][0]["message"]["content"]
            # arguments = response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            arguments = response.choices[0].message.tool_calls[0].function.arguments
            try:
                result = json.loads(arguments)
            except:
                result = arguments
            finish_reason = response.choices[0].finish_reason
            response_time = 0 # fake time, will be deprecated in the future
            response_dict = {
                "result": result,
                "finish_reason": finish_reason,
                "name": file_name,
                "time": response_time,
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
            print('_'*100)
            print(file_name)
            print(e)
            if response is not None:
                arguments = response.choices[0].message.tool_calls[0].function.arguments
                try:
                    result = json.loads(arguments)
                except:
                    result = arguments
                finish_reason = response.choices[0].finish_reason
                response_time = 0 # fake time, will be deprecated in the future
                response_dict = {
                    "result": result,
                    "finish_reason": finish_reason,
                    "name": file_name,
                    "time": response_time,
                }
                return response_dict
            return None
        except json.decoder.JSONDecodeError as e:
            count += 1
            if count > json_count_repeat:
                return None


def request_rewritter(client, report_path, model):
    report = report_path.split("/")[-1].split(".")[0]
    extracted_dir = './report_phases/0Extracted/'
    rewrited_dir = './report_phases/1Rewriter/'
    
    mitre_json_path = './aux_files/mitre.json'
    with open(mitre_json_path, 'r') as f:
        mitre = json.load(f)

    extracted_path = extracted_dir + report + '.txt'
    response_dict = request_rewriting(extracted_path, mitre, report, client, model)
    with open(rewrited_dir + report + '.json', 'w', encoding='utf-8') as f:
        json.dump(response_dict['result'], f, indent=2)
        print(response_dict['result'])