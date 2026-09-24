import json
with open(r'C:\Users\SHAMBHAVI PATIL\.gemini\antigravity\brain\4166c529-7fc6-483f-8008-3f2a9e3c0f4f\.system_generated\logs\transcript_full.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        if data.get('type') == 'USER_INPUT':
            with open('prompt_out.txt', 'w', encoding='utf-8') as out:
                out.write(data['content'])
            break
