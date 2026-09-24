import os

filepath = "backend/app/api/analyze.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the inner loop reading logic to enforce a GLOBAL cap of 100 samples
old_logic = """                                        json_lines_to_scan.append(obj)
                                        lines_read += 1
                                        if lines_read >= 250: # Limit dataset batches so UI doesn't crash
                                            break"""

new_logic = """                                        json_lines_to_scan.append(obj)
                                        if len(json_lines_to_scan) >= 100: # GLOBAL limit so UI doesn't crash and analysis is fast
                                            break
                            if len(json_lines_to_scan) >= 100:
                                break"""

if old_logic in content:
    content = content.replace(old_logic, new_logic)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print("Successfully updated analyze.py with global batch limit of 100.")
else:
    print("Could not find the target logic in analyze.py")
