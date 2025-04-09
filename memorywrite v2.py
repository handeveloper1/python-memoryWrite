import psutil
import ctypes
import ctypes.wintypes as wintypes
import time
from colorama import Fore, Style, init


init(autoreset=True)
PROCESS_ALL_ACCESS = 0x1F0FFF


def get_pid_by_name(process_name):
    """Get the PID of the process by its name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None


def open_process(pid):
    """Open the process with all access rights."""
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


def get_module_base_address(pid, module_name):
    """Get the base address of the specified module in the given process."""
    module_name = module_name.lower()
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, pid)
    module_entry = ctypes.create_string_buffer(568)

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("th32ModuleID", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("GlblcntUsage", wintypes.DWORD),
                    ("ProccntUsage", wintypes.DWORD),
                    ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
                    ("modBaseSize", wintypes.DWORD),
                    ("hModule", wintypes.HMODULE),
                    ("szModule", ctypes.c_char * 256),
                    ("szExePath", ctypes.c_char * 260)]

    module_entry = MODULEENTRY32()
    module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)

    if ctypes.windll.kernel32.Module32First(snapshot, ctypes.byref(module_entry)):
        while True:
            if module_entry.szModule.decode('utf-8').lower() == module_name:
                ctypes.windll.kernel32.CloseHandle(snapshot)
                return ctypes.addressof(module_entry.modBaseAddr.contents)
            if not ctypes.windll.kernel32.Module32Next(snapshot, ctypes.byref(module_entry)):
                break

    ctypes.windll.kernel32.CloseHandle(snapshot)
    return None


def write_memory(process_handle, address, data):
    """Write memory to a process."""
    size = len(data)
    buffer = ctypes.create_string_buffer(data)
    bytes_written = ctypes.c_size_t(0)
    if not ctypes.windll.kernel32.WriteProcessMemory(process_handle, ctypes.c_void_p(address), buffer, size,
                                                     ctypes.byref(bytes_written)):
        raise ctypes.WinError()
    return bytes_written.value



def print_message(message):
    icon = Fore.GREEN + "  ✔  "
    print(icon + Fore.GREEN + message)
    time.sleep(1)

def enerci():
    process_name = "WildForest.exe"
    module_name = "GameAssembly.dll"
    offset = 0x3BE6602
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\xB9\x30\x00\x00\x00'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    print_message(" Sınırsız Enerji Aktif Edildi.")



def unit():
    process_name = "WildForest.exe"
    module_name = "GameAssembly.dll"
    offset = 0x3A96C28
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    #print("Memory write operation completed.")

    offset = 0x3A96C29
    # new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    ##print("Memory write operation completed.")

    offset = 0x3A96C2A
    # new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    print_message(" Sınırsız Unit Aktif Edildi.")



def zpawn():

    process_name = "WildForest.exe"
    module_name = "GameAssembly.dll"
    offset = 0x3BD79B0
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    #print("Memory write operation completed.")
    offset = 0x3BD79B1
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    #print("Memory write operation completed.")
    offset = 0x3BD79B2
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    #print("Memory write operation completed.")
    offset = 0x3BD79B3
    #new_bytes = b'\x8B\x08'  # New bytes to write
    new_bytes = b'\x90'

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"Process '{process_name}' not found.")
        return

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process.")
        return

    base_address = get_module_base_address(pid, module_name)
    if base_address is None:
        print(f"Module '{module_name}' not found in process.")
        return

    target_address = base_address + offset
    #print(f"Writing to address: {hex(target_address)}")

    write_memory(process_handle, target_address, new_bytes)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    print_message(" Bekleme Süresi Kaldırıldı.")


enerci()
unit()
zpawn()

while 1:
    pass