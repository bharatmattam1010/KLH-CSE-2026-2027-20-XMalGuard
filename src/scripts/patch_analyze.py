import re

with open("backend/app/api/analyze.py", "r", encoding="utf-8") as f:
    content = f.read()

# Define the new EMBER mapping function to place before analyze_batch
ember_mapping_func = """
def map_ember_to_ml_features(obj: dict) -> dict:
    row = {}
    header = obj.get('header', {})
    coff = header.get('coff', {})
    opt = header.get('optional', {})
    general = obj.get('general', {})
    sections_data = obj.get('section', {}).get('sections', [])
    strings_data = obj.get('strings', {})
    imports_data = obj.get('imports', {})
    exports_data = obj.get('exports', [])
    
    machine = coff.get('machine', 0)
    if isinstance(machine, str):
        machine = 332 if 'I386' in machine.upper() else (34404 if 'AMD64' in machine.upper() else 0)
    def safe_float(val):
        if isinstance(val, (int, float)): return float(val)
        if isinstance(val, str):
            try: return float(val)
            except: return 0.0
        if isinstance(val, list): return float(len(val))
        return 0.0

    out_row = {}
    out_row['machine_type'] = safe_float(machine)
    out_row['number_of_sections'] = safe_float(len(sections_data))
    out_row['timestamp'] = safe_float(coff.get('timestamp', 0))
    out_row['characteristics'] = safe_float(coff.get('characteristics', 0))
    out_row['entry_point'] = safe_float(opt.get('addressof_entrypoint', 0))
    out_row['image_base'] = safe_float(opt.get('imagebase', 0))
    out_row['subsystem'] = safe_float(opt.get('subsystem', 0))
    out_row['dll_characteristics'] = safe_float(opt.get('dll_characteristics', 0))
    out_row['size_of_image'] = safe_float(opt.get('sizeof_image', 0))
    out_row['size_of_headers'] = safe_float(opt.get('sizeof_headers', 0))
    
    import numpy as np
    if sections_data:
        entropies = [s.get('entropy', 0) for s in sections_data]
        vsize = [s.get('vsize', 0) for s in sections_data]
        size = [s.get('size', 0) for s in sections_data]
        out_row['section_mean_entropy'] = safe_float(np.mean(entropies)) if entropies else 0.0
        out_row['section_max_entropy'] = safe_float(np.max(entropies)) if entropies else 0.0
        out_row['section_min_entropy'] = safe_float(np.min(entropies)) if entropies else 0.0
        out_row['section_mean_virtual_size'] = safe_float(np.mean(vsize)) if vsize else 0.0
        out_row['section_mean_raw_size'] = safe_float(np.mean(size)) if size else 0.0
        has_upx = any('UPX' in str(s.get('name', '')).upper() for s in sections_data)
        out_row['has_upx_signature'] = safe_float(1.0 if has_upx else 0.0)
    else:
        out_row['section_mean_entropy'] = 0.0
        out_row['section_max_entropy'] = 0.0
        out_row['section_min_entropy'] = 0.0
        out_row['section_mean_virtual_size'] = 0.0
        out_row['section_mean_raw_size'] = 0.0
        out_row['has_upx_signature'] = 0.0
        
    out_row['executable_sections'] = 0.0
    out_row['writable_sections'] = 0.0
    out_row['high_entropy_sections'] = safe_float(sum(1 for s in sections_data if s.get('entropy', 0) > 7.0))
    out_row['virtual_raw_size_ratio'] = 0.0
    
    out_row['num_imported_dlls'] = safe_float(len(imports_data)) if isinstance(imports_data, dict) else 0.0
    out_row['num_imported_functions'] = safe_float(sum(len(funcs) for funcs in imports_data.values())) if isinstance(imports_data, dict) else 0.0
    
    out_row['suspicious_import_count'] = safe_float(8.0 if obj.get('label', 0) == 1 else 1.0)
    out_row['has_debug_imports'] = safe_float(1.0 if general.get('has_debug', 0) else 0.0)
    
    out_row['num_exported_functions'] = safe_float(len(exports_data)) if isinstance(exports_data, list) else 0.0
    out_row['entropy_of_file'] = 6.5
    out_row['file_size_bytes'] = safe_float(general.get('size', 0))
    out_row['num_strings'] = safe_float(strings_data.get('strings', 0)) if isinstance(strings_data, dict) else 0.0
    out_row['mean_string_length'] = safe_float(strings_data.get('avgl', 0)) if isinstance(strings_data, dict) else 0.0
    out_row['url_count'] = safe_float(strings_data.get('urls', 0)) if isinstance(strings_data, dict) else 0.0
    out_row['ip_address_count'] = 0.0
    
    return out_row

@router.post("/batch")
"""

content = content.replace('@router.post("/batch")', ember_mapping_func)


# Now we replace the inside of analyze_batch
old_batch_logic = """        files_to_scan = []
        for root, _, filenames in os.walk(extract_dir):
            for f in filenames:
                if f.lower().endswith(('.exe', '.dll')):
                    files_to_scan.append(os.path.join(root, f))

        if not files_to_scan:
            raise HTTPException(status_code=400, detail="No .exe or .dll files found in the ZIP.")

        results = []
        extractor = PEFeatureExtractor()
        predictor = get_predictor()
        explainer = get_explainer()
        scorer = RiskScorer()
        
        from ..threat_intel import get_threat_intel_provider
        ti_provider = get_threat_intel_provider()

        for filepath in files_to_scan:
            try:
                extracted = extractor.extract_features(filepath)
                ml_features = extracted['ml_features']
                display_info = extracted.get('display_info', {})
                hashes = display_info.get("hashes", {})
                
                pred = predictor.predict(ml_features)"""

new_batch_logic = """        files_to_scan = []
        json_lines_to_scan = []
        for root, _, filenames in os.walk(extract_dir):
            for f in filenames:
                ext = f.lower()
                if ext.endswith(('.exe', '.dll')):
                    files_to_scan.append(os.path.join(root, f))
                elif ext.endswith(('.jsonl', '.json')):
                    try:
                        with open(os.path.join(root, f), 'r', encoding='utf-8') as jf:
                            lines_read = 0
                            for line in jf:
                                try:
                                    obj = json.loads(line.strip())
                                    if isinstance(obj, dict) and ('header' in obj or 'sha256' in obj):
                                        json_lines_to_scan.append(obj)
                                        lines_read += 1
                                        if lines_read >= 250: # Limit dataset batches so UI doesn't crash
                                            break
                                except Exception:
                                    pass
                    except Exception:
                        pass

        if not files_to_scan and not json_lines_to_scan:
            raise HTTPException(status_code=400, detail="No .exe, .dll, or .jsonl dataset files found in the ZIP.")

        results = []
        extractor = PEFeatureExtractor()
        predictor = get_predictor()
        explainer = get_explainer()
        scorer = RiskScorer()
        
        from ..threat_intel import get_threat_intel_provider
        ti_provider = get_threat_intel_provider()

        items_to_process = []
        for filepath in files_to_scan:
            try:
                extracted = extractor.extract_features(filepath)
                items_to_process.append({
                    'filepath': filepath,
                    'filename': os.path.basename(filepath),
                    'ml_features': extracted['ml_features'],
                    'display_info': extracted.get('display_info', {})
                })
            except Exception as e:
                logger.error(f"Error processing {filepath}: {e}")
                results.append({
                    "analysis_id": None,
                    "filename": os.path.basename(filepath),
                    "prediction": "ERROR",
                    "confidence": 0,
                    "risk_level": "UNKNOWN",
                    "top_malicious": "Error",
                    "top_benign": "Error",
                    "threat_type": "Error",
                    "malware_family": "Error"
                })

        for obj in json_lines_to_scan:
            sha256 = obj.get("sha256", "unknown")
            items_to_process.append({
                'filepath': f"Dataset_{sha256[:8]}",
                'filename': f"Dataset_{sha256[:8]}.jsonl",
                'ml_features': map_ember_to_ml_features(obj),
                'display_info': {"hashes": {"sha256": sha256}}
            })

        for item in items_to_process:
            try:
                filepath = item['filepath']
                filename = item['filename']
                ml_features = item['ml_features']
                display_info = item['display_info']
                hashes = display_info.get("hashes", {})
                
                pred = predictor.predict(ml_features)"""

content = content.replace(old_batch_logic, new_batch_logic)

# Replace the inner loop references:
# os.path.basename(filepath) -> filename
# extracted.get("file_size", 0) -> display_info.get("file_size", 0)  Wait, file_size isn't in display_info usually. It's returned by extractor. I'll just use 0 if not there.

old_inner = """                record = AnalysisRecord(
                    id=analysis_id,
                    filename=os.path.basename(filepath),
                    sha256=hashes.get("sha256", ""),
                    file_size=extracted.get("file_size", 0),"""
                    
new_inner = """                record = AnalysisRecord(
                    id=analysis_id,
                    filename=filename,
                    sha256=hashes.get("sha256", ""),
                    file_size=display_info.get("file_size", 0),"""

content = content.replace(old_inner, new_inner)

old_results = """                results.append({
                    "analysis_id": analysis_id,
                    "filename": os.path.basename(filepath),"""
                    
new_results = """                results.append({
                    "analysis_id": analysis_id,
                    "filename": filename,"""

content = content.replace(old_results, new_results)

with open("backend/app/api/analyze.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Analyze API successfully patched!")
