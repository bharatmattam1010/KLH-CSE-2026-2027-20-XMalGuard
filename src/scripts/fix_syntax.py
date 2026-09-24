import os

filepath = "backend/app/api/analyze.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

bad_logic = """                                        json_lines_to_scan.append(obj)
                                        if len(json_lines_to_scan) >= 100: # GLOBAL limit so UI doesn't crash and analysis is fast
                                            break
                            if len(json_lines_to_scan) >= 100:
                                break
                                except Exception:
                                    pass"""

good_logic = """                                        json_lines_to_scan.append(obj)
                                        if len(json_lines_to_scan) >= 100:
                                            break
                                except Exception:
                                    pass
                            if len(json_lines_to_scan) >= 100:
                                break"""

content = content.replace(bad_logic, good_logic)
with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed syntax error in analyze.py")
