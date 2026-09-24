import logging

logger = logging.getLogger(__name__)

SUSPICIOUS_APIS = {
    'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
    'NtUnmapViewOfSection', 'QueueUserAPC', 'SetWindowsHookEx', 'GetProcAddress',
    'LoadLibraryA', 'LoadLibraryW', 'URLDownloadToFile', 'InternetOpen',
    'HttpOpenRequest', 'WinExec', 'ShellExecute', 'CreateProcess',
    'RegSetValueEx', 'RegCreateKeyEx', 'CryptEncrypt', 'CryptDecrypt',
    'IsDebuggerPresent', 'GetTickCount', 'Sleep', 'NtQueryInformationProcess',
    'OpenProcess'
}

debug_imports = {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'GetTickCount', 'OutputDebugString'}
network_imports = {'InternetOpen', 'HttpOpenRequest', 'URLDownloadToFile', 'WSAStartup', 'connect', 'send', 'recv', 'InternetConnect', 'HttpSendRequest', 'socket'}
crypto_imports = {'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext', 'CryptHashData', 'CryptDeriveKey'}
process_imports = {'CreateProcess', 'OpenProcess', 'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'NtUnmapViewOfSection', 'QueueUserAPC', 'TerminateProcess'}
registry_imports = {'RegSetValueEx', 'RegCreateKeyEx', 'RegOpenKeyEx', 'RegDeleteKey', 'RegDeleteValue'}

def analyze_imports(pe) -> dict:
    """
    Analyzes imports of a PE file to extract ML features and display info.
    
    Args:
        pe (pefile.PE): A parsed pefile.PE object.
        
    Returns:
        dict: Features extracted from the imports.
    """
    features = {
        'num_imported_dlls': 0,
        'num_imported_functions': 0,
        'suspicious_import_count': 0,
        'has_debug_imports': 0,
        'has_network_imports': 0,
        'has_crypto_imports': 0,
        'has_process_imports': 0,
        'has_registry_imports': 0,
        'imported_dlls': [],
        'suspicious_apis_found': []
    }
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return features
        
    try:
        imported_dlls = []
        suspicious_apis = []
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll:
                dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                imported_dlls.append(dll_name)
                features['num_imported_dlls'] += 1
                
            for imp in entry.imports:
                features['num_imported_functions'] += 1
                if imp.name:
                    func_name = imp.name.decode('utf-8', 'ignore')
                    
                    if func_name in SUSPICIOUS_APIS:
                        features['suspicious_import_count'] += 1
                        suspicious_apis.append(func_name)
                        
                    if func_name in debug_imports:
                        features['has_debug_imports'] = 1
                    if func_name in network_imports:
                        features['has_network_imports'] = 1
                    if func_name in crypto_imports:
                        features['has_crypto_imports'] = 1
                    if func_name in process_imports:
                        features['has_process_imports'] = 1
                    if func_name in registry_imports:
                        features['has_registry_imports'] = 1
                        
        features['imported_dlls'] = imported_dlls
        features['suspicious_apis_found'] = suspicious_apis
        
    except Exception as e:
        logger.error(f"Error analyzing imports: {e}")
        
    return features
