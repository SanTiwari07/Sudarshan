with open('docs/api/ENDPOINTS.md', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace "None" with "Bearer Token (Analyst scoped)" for the /api/runtime endpoints
lines = content.split('\n')
for i, line in enumerate(lines):
    if '| `GET /api/runtime/' in line:
        lines[i] = line.replace('| None |', '| Bearer Token (Analyst scoped) |')

with open('docs/api/ENDPOINTS.md', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print("Patched ENDPOINTS.md")
