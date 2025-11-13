import sys
import os
from openai import OpenAI
from secrets import openai_key
import rewritter

current_model = 'gpt-4o'
client = OpenAI(api_key=openai_key)

def find_report(report):
    for root, dirs, files in os.walk("."):
        for file in files:
            if(file == report.split("/")[-1]):
                print("Report " + report + " found, proceeding to execution")
                return os.path.join(root, file)
    print("Report " + report + " not found in base directory")
    sys.exit(1)

def main():
    if(len(sys.argv) != 2):
        print("Only one argument allowed")
        sys.exit(1)
    else:
        report = sys.argv[1]
        print("Selected report " + report)
        report_path = find_report(report)
        print(report_path)
    rewritter.request_rewritter(client, report_path, current_model)
            
    
    
    
if __name__ == "__main__":
    main()
    
response = client.responses.create(
    model=current_model,
    instructions="You are an assistant that matches target scan outputs with adversary profiles for attack simulation.",
    input="prompt"
)
answer = response.output_text