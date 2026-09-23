def convert_qmark_to_dollar(sql: str) -> str:
    # A simple parser to avoid replacing '?' inside quotes.
    in_single_quote = False
    in_double_quote = False
    param_idx = 1
    out = []
    
    i = 0
    while i < len(sql):
        c = sql[i]
        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            out.append(c)
        elif c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            out.append(c)
        elif c == '?' and not in_single_quote and not in_double_quote:
            out.append(f"${param_idx}")
            param_idx += 1
        else:
            out.append(c)
        i += 1
            
    return "".join(out)

print(convert_qmark_to_dollar("SELECT * FROM table WHERE col = '?' AND val = ?"))
print(convert_qmark_to_dollar("INSERT INTO tbl (id, \"val?u\") VALUES (?, ?)"))
