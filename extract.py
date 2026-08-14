import json
import sys

transcript_path = r'C:\Users\sansk\.gemini\antigravity\brain\168aad23-e709-463d-a2a1-ab986530a73d\.system_generated\logs\transcript_full.jsonl'
out_path = r'C:\Users\sansk\.gemini\antigravity\brain\168aad23-e709-463d-a2a1-ab986530a73d\scratch\extracted_reports.md'

with open(transcript_path, 'r', encoding='utf-8') as f, open(out_path, 'w', encoding='utf-8') as out:
    for i, line in enumerate(f):
        data = json.loads(line)
        content = data.get('content', '')
        if data.get('source') == 'SYSTEM' and len(content) > 500:
            out.write(f'# MSG {i}\n\n' + content + '\n\n')
