# Passed to: git filter-repo --commit-callback "$(Get-Content -Raw ...)"
# Strips Cursor trailers from messages; author/committer dates are unchanged.
import re

msg = commit.message.decode("utf-8", errors="replace")
pat = re.compile(
    r"(?i)cursoragent@cursor\.com|199161495\+cursoragent@users\.noreply\.github\.com"
    r"|^co-authored-by:\s*cursor|^made-with:\s*cursor"
)
lines = [ln for ln in msg.splitlines() if not pat.search(ln)]
commit.message = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
