"""Current-user Windows Credential Manager storage; never writes secret files."""
import ctypes
from ctypes import wintypes
import json
import os

TARGET = 'Hyunode/OpenAI'


class Credential(ctypes.Structure):
    _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD),
                ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
                ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD),
                ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)), ('Persist', wintypes.DWORD),
                ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p),
                ('TargetAlias', wintypes.LPWSTR), ('UserName', wintypes.LPWSTR)]


def api():
    if os.name != 'nt':
        raise OSError('Windows 자격 증명 관리자 기능은 Windows에서만 지원합니다.')
    dll = ctypes.WinDLL('Advapi32.dll', use_last_error=True)
    dll.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.POINTER(ctypes.POINTER(Credential))]
    dll.CredReadW.restype = wintypes.BOOL
    dll.CredWriteW.argtypes = [ctypes.POINTER(Credential), wintypes.DWORD]
    dll.CredWriteW.restype = wintypes.BOOL
    dll.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    dll.CredDeleteW.restype = wintypes.BOOL
    dll.CredFree.argtypes = [ctypes.c_void_p]
    dll.CredFree.restype = None
    return dll


def read_saved(target=TARGET):
    if os.name != 'nt':
        return {}
    dll = api()
    pointer = ctypes.POINTER(Credential)()
    if not dll.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == 1168:  # ERROR_NOT_FOUND
            return {}
        raise OSError('Windows 자격 증명을 읽지 못했습니다.')
    try:
        raw = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
        value = json.loads(raw.decode('utf-8'))
        if not isinstance(value, dict) or not all(isinstance(value.get(k), str) for k in ('key', 'model')):
            raise ValueError('저장된 API 설정 형식이 올바르지 않습니다. 다시 설정하세요.')
        return {'key': value['key'], 'model': value['model']}
    finally:
        dll.CredFree(pointer)


def save(key, model, target=TARGET):
    key, model = key.strip(), model.strip()
    if not key or not model or any(c.isspace() for c in key + model):
        raise ValueError('공백 없는 API 키와 모델 ID를 입력하세요.')
    raw = json.dumps({'key': key, 'model': model}).encode('utf-8')
    if len(raw) > 2560:
        raise ValueError('입력 길이 제한을 초과했습니다.')
    blob = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    entry = Credential()
    entry.Type = 1  # CRED_TYPE_GENERIC
    entry.TargetName = target
    entry.Comment = 'Hyunode private OpenAI API settings'
    entry.UserName = 'Hyunode'
    entry.CredentialBlobSize = len(raw)
    entry.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
    entry.Persist = 2  # Same user and machine, across logons; not enterprise roaming.
    try:
        if not api().CredWriteW(ctypes.byref(entry), 0):
            raise OSError('Windows 자격 증명을 저장하지 못했습니다.')
    finally:
        ctypes.memset(blob, 0, len(raw))


def delete(target=TARGET):
    if not api().CredDeleteW(target, 1, 0) and ctypes.get_last_error() != 1168:
        raise OSError('저장된 API 설정을 삭제하지 못했습니다.')


def resolve():
    # An explicitly supplied environment configuration always takes precedence.
    key, model = os.getenv('OPENAI_API_KEY', ''), os.getenv('OPENAI_MODEL', '')
    if key or model:
        return {'key': key, 'model': model, 'source': 'environment'}
    saved = read_saved()
    return {'key': saved.get('key', ''), 'model': saved.get('model', ''),
            'source': 'windows_credential_manager' if saved else 'not_configured'}
