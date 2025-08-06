import serial
import struct
import json
import sys
import os
import threading

try:
    import keyboard
except ImportError:
    print("Please install the 'keyboard' module: pip install keyboard")
    sys.exit(1)

# Load the hash table
with open("log_hash_table.json", "r", encoding="utf-8") as f:
    hash_table = json.load(f)

log_levels = {
    0: "DEBUG",
    1: "INFO",
    2: "WARN",
    3: "ERROR",
    4: "FATAL"
}

def parse_log_entry(entry):
    if len(entry) < 16:
        print("Entry too short!")
        return

    entry_length, _padding, timestamp, string_hash, level, num_params, reserved1, reserved2 = struct.unpack('<HHIIBBBB', entry[:16])
    offset = 16

    params = []
    for _ in range(num_params):
        if offset + 4 > len(entry):
            print("ParamHeader out of bounds!")
            return
        index, typ, size, _pad = struct.unpack('<BBBB', entry[offset:offset+4])
        params.append({'index': index, 'type': typ, 'size': size})
        offset += 4

    param_values = []
    for p in params:
        if offset + p['size'] > len(entry):
            print("Param data out of bounds!")
            return
        data = entry[offset:offset+p['size']]
        if p['type'] == 1:  # int32_t
            val = struct.unpack('<i', data)[0]
        elif p['type'] == 2:  # uint32_t
            val = struct.unpack('<I', data)[0]
        elif p['type'] == 3:  # float
            val = struct.unpack('<f', data)[0]
        elif p['type'] == 4:  # int16_t
            val = struct.unpack('<h', data)[0]
        elif p['type'] == 5:  # uint16_t
            val = struct.unpack('<H', data)[0]
        elif p['type'] == 6:  # int8_t
            val = struct.unpack('<b', data)[0]
        elif p['type'] == 7:  # uint8_t
            val = struct.unpack('<B', data)[0]
        else:
            val = data.hex()
        param_values.append(val)
        offset += p['size']

    fmt = hash_table.get(f"{string_hash:08X}", f"<unknown:0x{string_hash:08X}>")
    level_str = log_levels.get(level, f"LVL{level}")

    try:
        msg = fmt % tuple(param_values)
    except Exception:
        msg = fmt + " " + str(param_values)
    print(f"[{timestamp:10d}] [{level_str:5s}] {msg}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("[Screen cleared. Press 'c' to clear again.]")

def listen_for_clear():
    while True:
        keyboard.wait('c')
        clear_screen()

def main():
    if len(sys.argv) < 3:
        print("Usage: python uart_log_viewer.py COMx BAUDRATE")
        print("Example: python uart_log_viewer.py COM3 115200")
        return

    port = sys.argv[1]
    baud = int(sys.argv[2])

    try:
        ser = serial.Serial(port, baud, timeout=0.1)
    except Exception as e:
        print(f"Could not open serial port {port}: {e}")
        return

    print(f"Listening on {port} at {baud} baud...")
    print("Press 'c' to clear the screen at any time. (Do NOT use Ctrl+C)")

    threading.Thread(target=listen_for_clear, daemon=True).start()

    buffer = bytearray()
    while True:
        try:
            data = ser.read(1024)
            if data:
                buffer.extend(data)
                while len(buffer) >= 2:
                    entry_length = struct.unpack('<H', buffer[:2])[0]
                    if len(buffer) < entry_length:
                        break
                    entry = buffer[:entry_length]
                    parse_log_entry(entry)
                    buffer = buffer[entry_length:]
        except KeyboardInterrupt:
            print("\n[Ctrl+C detected, but script will keep running. Use 'c' to clear the screen.]")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()