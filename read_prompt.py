import json
with open('first_prompt.json', 'r', encoding='utf-16') as f:
    line = f.read().split('.jsonl:', 1)[1] # remove filename prefix added by Select-String
    data = json.loads(line.strip())
    print(data['content'])
