import sys
import argparse
import math
import os
import json
import importlib.util
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from pathlib import Path

# ECC Magic byte for auto-detection of error-corrected payloads
ECC_MAGIC_BYTE = 0xEC
DEFAULT_ECC_SYMBOLS = 10

# Verbose mode (disabled by default, enabled with --verbose)
VERBOSE = False

def log_info(msg: str):
    """Print info message only if verbose mode is enabled."""
    if VERBOSE:
        print(f"[INFO] {msg}", file=sys.stderr)

def log_warn(msg: str):
    """Print warning message only if verbose mode is enabled."""
    if VERBOSE:
        print(f"[WARN] {msg}", file=sys.stderr)

# ==========================================
#  FRAMEWORK: Abstract Base Class & Registry
# ==========================================

class CipherStrategy(ABC):
    """Abstract base class that all ciphers must implement."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """The command-line name for this cipher."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description for help text."""
        pass

    @abstractmethod
    def encode(self, text: str) -> str:
        pass

    @abstractmethod
    def decode(self, text: str) -> str:
        pass

CIPHER_REGISTRY = {}

def register_cipher(cls):
    """Decorator to auto-register ciphers."""
    cipher = cls()
    CIPHER_REGISTRY[cipher.name] = cipher
    return cls

# ==========================================
#  STEGANOGRAPHY: Watermark Engine
# ==========================================

class WatermarkEngine:
    """
    Injects and retrieves invisible metadata using zero-width characters.
    
    Protocol:
    - S (Start/Stop Sentinel): \u2060 (Word Joiner)
    - 0 (Bit Zero): \u200B (Zero Width Space)
    - 1 (Bit One):  \u200C (Zero Width Non-Joiner)
    
    Format: [S] [Binary String of Cipher Name] [S] [Ciphertext]
    """
    
    SENTINEL = '\u2060'
    ZERO = '\u200B'
    ONE = '\u200C'

    @staticmethod
    def _str_to_bits(s: str) -> str:
        bytes_val = s.encode('utf-8')
        return "".join(f"{b:08b}" for b in bytes_val)

    @staticmethod
    def _bits_to_str(bits: str) -> str:
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            chars.append(chr(int(byte, 2)))
        return "".join(chars)

    @classmethod
    def inject(cls, text: str, cipher_name: str) -> str:
        """Prefixes text with an invisible watermark of the cipher name."""
        bits = cls._str_to_bits(cipher_name)
        invisible_payload = bits.replace('0', cls.ZERO).replace('1', cls.ONE)
        header = f"{cls.SENTINEL}{invisible_payload}{cls.SENTINEL}"
        return header + text

    @classmethod
    def detect(cls, text: str) -> Tuple[Optional[str], str]:
        """
        Scans for invisible watermark.
        Returns: (detected_cipher_name, clean_text_without_watermark)
        """
        if not text.startswith(cls.SENTINEL):
            return None, text

        end_index = text.find(cls.SENTINEL, 1)
        if end_index == -1:
            return None, text

        raw_payload = text[1:end_index]
        
        if any(c not in (cls.ZERO, cls.ONE) for c in raw_payload):
            return None, text

        try:
            bits = raw_payload.replace(cls.ZERO, '0').replace(cls.ONE, '1')
            cipher_name = cls._bits_to_str(bits)
            clean_text = text[end_index + 1:] 
            return cipher_name, clean_text
        except Exception:
            return None, text

# ==========================================
#  ERROR CORRECTION: Reed-Solomon Engine
# ==========================================

class ErrorCorrection:
    """
    Reed-Solomon error correction wrapper.
    Adds ECC bytes to data for corruption recovery.
    
    Uses a magic byte prefix (0xEC) for auto-detection on decode.
    """
    
    @staticmethod
    def is_available() -> bool:
        """Check if reedsolo library is installed."""
        try:
            import reedsolo
            return True
        except ImportError:
            return False
    
    @staticmethod
    def encode(data: bytes, ecc_symbols: int) -> bytes:
        """
        Add Reed-Solomon ECC to data.
        Returns: [MAGIC_BYTE] + [ECC_SYMBOLS_COUNT] + [RS_ENCODED_DATA]
        """
        if ecc_symbols <= 0:
            return data
        
        try:
            from reedsolo import RSCodec
        except ImportError:
            log_warn("reedsolo not installed. ECC disabled. Install with: pip install reedsolo")
            return data
        
        rsc = RSCodec(ecc_symbols)
        encoded = rsc.encode(data)
        # Prefix with magic byte and ECC symbol count for auto-detection
        return bytes([ECC_MAGIC_BYTE, ecc_symbols]) + encoded
    
    @staticmethod
    def decode(data: bytes, ecc_symbols: int = None) -> Tuple[bytes, bool, int]:
        """
        Decode and repair Reed-Solomon protected data.
        
        Auto-detection: Only applies ECC if magic byte (0xEC) is present.
        The ecc_symbols parameter is ignored unless magic byte is missing
        AND ecc_symbols > 0 (for legacy/forced mode).
        
        Args:
            data: Input bytes (possibly with ECC prefix)
            ecc_symbols: Force ECC symbols (only used if no magic byte found)
        
        Returns:
            (decoded_data, had_ecc, errors_corrected)
        """
        if len(data) < 2:
            return data, False, 0
        
        # Auto-detect ECC from magic byte (primary detection method)
        if data[0] == ECC_MAGIC_BYTE:
            ecc_symbols = data[1]
            data = data[2:]  # Strip magic header
            had_ecc = True
        else:
            # No magic byte = no ECC was applied during encoding
            # Return data as-is (don't attempt ECC decode on non-ECC data)
            return data, False, 0
        
        if ecc_symbols <= 0:
            return data, False, 0
        
        try:
            from reedsolo import RSCodec, ReedSolomonError
        except ImportError:
            log_warn("reedsolo not installed. Cannot decode ECC data.")
            return data, had_ecc, 0
        
        try:
            rsc = RSCodec(ecc_symbols)
            decoded, _, errata_pos = rsc.decode(data)
            errors_corrected = len(errata_pos) if errata_pos else 0
            return bytes(decoded), had_ecc, errors_corrected
        except Exception as e:
            log_warn(f"ECC decode failed: {e}. Data may be corrupted beyond repair.")
            return data, had_ecc, -1  # -1 indicates failure

# ==========================================
#  PLUGIN SYSTEM: Dynamic Cipher Loading
# ==========================================

def load_plugins(plugin_dir: str = None) -> List[str]:
    """
    Load cipher plugins from a directory with manifest.json.
    
    Args:
        plugin_dir: Path to plugins directory (default: ./plugins relative to script)
    
    Returns:
        List of successfully loaded plugin names
    """
    if plugin_dir is None:
        script_dir = Path(__file__).parent
        plugin_dir = script_dir / "plugins"
    else:
        plugin_dir = Path(plugin_dir)
    
    if not plugin_dir.exists():
        return []
    
    manifest_path = plugin_dir / "manifest.json"
    if not manifest_path.exists():
        log_warn(f"No manifest.json in {plugin_dir}. Skipping plugin loading.")
        return []
    
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log_warn(f"Failed to read manifest.json: {e}")
        return []
    
    loaded = []
    plugins_list = manifest.get("plugins", [])
    
    for entry in plugins_list:
        filename = entry.get("file")
        expected_cipher = entry.get("cipher")
        
        if not filename:
            continue
        
        filepath = plugin_dir / filename
        if not filepath.exists():
            log_warn(f"Plugin file not found: {filepath}")
            continue
        
        try:
            spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                # Make our framework available to plugins
                module.CipherStrategy = CipherStrategy
                module.register_cipher = register_cipher
                spec.loader.exec_module(module)
                
                if expected_cipher and expected_cipher in CIPHER_REGISTRY:
                    loaded.append(expected_cipher)
                elif expected_cipher:
                    log_warn(f"Plugin {filename} did not register cipher '{expected_cipher}'")
                else:
                    loaded.append(filename)
        except Exception as e:
            log_warn(f"Failed to load plugin {filename}: {e}")
    
    return loaded

# ==========================================
#  METHOD 1: ZigZag (Formerly ZZ0)
# ==========================================

@register_cipher
class ZigZagCipher(CipherStrategy):
    name = "zigzag" 
    description = "Legacy Tally-based Zig-Zag (A=1 dot, Z=26 dots). Variable height."

    # Braille bitmasks (1-6 standard)
    DOTS = {1: 0x01, 2: 0x02, 3: 0x04, 4: 0x08, 5: 0x10, 6: 0x20}
    BRAILLE_OFFSET = 0x2800
    PATH_A = [1, 5, 3] # Left-Heavy
    PATH_B = [4, 2, 6] # Right-Heavy

    def _get_a26(self, c: str) -> int:
        if not c or not c.isalpha(): return 0
        return ord(c.upper()) - 64

    def _from_a26(self, v: int) -> str:
        return chr(v + 64) if 1 <= v <= 26 else " "

    def encode(self, text: str) -> str:
        if not text: return ""
        width = math.ceil(len(text) / 2)
        pairs = []
        for i in range(width):
            c1 = text[i*2] if i*2 < len(text) else " "
            c2 = text[i*2+1] if i*2+1 < len(text) else " "
            pairs.append((self._get_a26(c1), self._get_a26(c2)))

        max_val = max((max(p1, p2) for p1, p2 in pairs), default=0)
        height = math.ceil(max_val / 3)
        if height == 0: return ""

        grid = [[self.BRAILLE_OFFSET for _ in range(width)] for _ in range(height)]

        for col, (v1, v2) in enumerate(pairs):
            for d_idx in range(v1):
                row = d_idx // 3
                sub_idx = d_idx % 3
                path = self.PATH_A if row % 2 == 0 else self.PATH_B
                grid[row][col] |= self.DOTS[path[sub_idx]]
            
            for d_idx in range(v2):
                row = d_idx // 3
                sub_idx = d_idx % 3
                path = self.PATH_B if row % 2 == 0 else self.PATH_A
                grid[row][col] |= self.DOTS[path[sub_idx]]

        return "\n".join("".join(chr(c) for c in row) for row in grid)

    def decode(self, text: str) -> str:
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines: return ""
        
        width = max(len(line) for line in lines)
        height = len(lines)
        results = []

        for col in range(width):
            tally_left = 0
            tally_right = 0
            
            for row in range(height):
                try:
                    char_code = ord(lines[row][col])
                except IndexError:
                    char_code = self.BRAILLE_OFFSET

                cell_val = char_code - self.BRAILLE_OFFSET
                if cell_val < 0 or cell_val > 0xFF: cell_val = 0
                
                p_left = self.PATH_A if row % 2 == 0 else self.PATH_B
                p_right = self.PATH_B if row % 2 == 0 else self.PATH_A
                
                for dot in p_left:
                    if cell_val & self.DOTS[dot]: tally_left += 1
                for dot in p_right:
                    if cell_val & self.DOTS[dot]: tally_right += 1
            
            results.append(self._from_a26(tally_left))
            results.append(self._from_a26(tally_right))
        
        return "".join(results).rstrip()

# ==========================================
#  METHOD 2: NT CMPRSSN v2 (Braille Integer v2)
# ==========================================

@register_cipher
class Int2Cipher(CipherStrategy):
    name = "int2"
    description = "Scrambles bits into a linear Zig-Zag of 8-dot Braille (Efficient). Supports ECC."

    BASE = 0x2800
    DOTS = {1: 0x01, 2: 0x02, 3: 0x04, 4: 0x08, 5: 0x10, 6: 0x20, 7: 0x40, 8: 0x80}
    MAP_ZIG = [1, 2, 3, 7, 4, 5, 6, 8]
    MAP_ZAG = [4, 5, 6, 8, 1, 2, 3, 7]

    def __init__(self):
        self.ecc_symbols = DEFAULT_ECC_SYMBOLS

    def _bytes_to_braille(self, data: bytes) -> str:
        """Convert raw bytes to Braille string using zig-zag mapping."""
        result = []
        for i, byte in enumerate(data):
            braille_val = 0
            mapping = self.MAP_ZIG if i % 2 == 0 else self.MAP_ZAG
            for bit in range(8):
                if (byte >> bit) & 1:
                    braille_val |= self.DOTS[mapping[bit]]
            result.append(chr(self.BASE + braille_val))
        return "".join(result)

    def _braille_to_bytes(self, text: str) -> bytearray:
        """Convert Braille string back to raw bytes."""
        clean_text = "".join(text.split())
        decoded_bytes = bytearray()
        for i, char in enumerate(clean_text):
            code = ord(char)
            if not (0x2800 <= code <= 0x28FF):
                continue
            val = code - self.BASE
            byte_val = 0
            mapping = self.MAP_ZIG if i % 2 == 0 else self.MAP_ZAG
            for bit in range(8):
                if val & self.DOTS[mapping[bit]]:
                    byte_val |= (1 << bit)
            decoded_bytes.append(byte_val)
        return decoded_bytes

    def encode(self, text: str, ecc_symbols: int = None) -> str:
        if not text:
            return ""
        if ecc_symbols is None:
            ecc_symbols = self.ecc_symbols
        
        data = text.encode('utf-8')
        
        # Apply ECC if enabled
        if ecc_symbols > 0:
            data = ErrorCorrection.encode(data, ecc_symbols)
        
        return self._bytes_to_braille(data)

    def decode(self, text: str, ecc_symbols: int = None) -> str:
        decoded_bytes = self._braille_to_bytes(text)
        
        if not decoded_bytes:
            return ""
        
        # Attempt ECC decode (auto-detects from magic byte)
        decoded_data, had_ecc, errors = ErrorCorrection.decode(bytes(decoded_bytes), ecc_symbols)
        
        if errors > 0:
            log_info(f"Corrected {errors} error(s) using Reed-Solomon.")
        elif errors < 0:
            log_warn("Data corruption detected but could not be repaired.")
        
        try:
            return decoded_data.decode('utf-8')
        except Exception:
            return f"[Raw Data]: {decoded_data.hex()}"

# ==========================================
#  METHOD 3: Integer Braille (1NT C0MPR3SS10N)
# ==========================================

@register_cipher
class IntegerCipher(CipherStrategy):
    name = "integer"
    description = "Encodes text as a single massive integer in Base-10 Braille."
    
    DIGITS = " ⠏⠋⠦⠇⠼⠙⠴⠹⠧"

    def __init__(self):
        self.char_map = {char: i for i, char in enumerate(self.DIGITS)}

    def encode(self, text: str) -> str:
        if not text: return ""
        num = int.from_bytes(text.encode('utf-8'), byteorder='big')
        if num == 0: return self.DIGITS[0]
        result = []
        base = len(self.DIGITS)
        while num > 0:
            result.append(self.DIGITS[num % base])
            num //= base
        return "".join(reversed(result))

    def decode(self, text: str) -> str:
        num = 0
        base = len(self.DIGITS)
        try:
            for c in text:
                if c in '\n\r': continue
                if c in ('\u200B', '\u200C', '\u2060'): continue 
                if c not in self.char_map: raise ValueError(f"Bad char '{c}'")
                num = num * base + self.char_map[c]
        except ValueError as e: return f"[ERROR] {e}"
        length = (num.bit_length() + 7) // 8
        try: return num.to_bytes(length, 'big').decode('utf-8')
        except: return "[ERROR] Decode failed."

# ==========================================
#  METHOD 4: ^2 (Squared aka QR code-style)
# ==========================================

@register_cipher
class SquareSpiralCipher(CipherStrategy):
    name = "square"
    description = "Packs data into a perfect N x N Braille square using a spiral fill. Supports ECC."

    BASE = 0x2800

    def __init__(self):
        self.ecc_symbols = DEFAULT_ECC_SYMBOLS

    def _spiral_fill(self, data: bytes, side: int) -> list:
        """Fill a grid in spiral order with data bytes."""
        grid = [[0 for _ in range(side)] for _ in range(side)]
        r, c = 0, 0
        dr, dc = 0, 1
        min_r, max_r, min_c, max_c = 0, side - 1, 0, side - 1
        
        for byte in data:
            grid[r][c] = byte
            next_r, next_c = r + dr, c + dc
            if not (min_r <= next_r <= max_r and min_c <= next_c <= max_c):
                dr, dc = dc, -dr
                if dr == 1:
                    min_r += 1
                elif dc == -1:
                    max_c -= 1
                elif dr == -1:
                    max_r -= 1
                elif dc == 1:
                    min_c += 1
                next_r, next_c = r + dr, c + dc
            r, c = next_r, next_c
        return grid

    def _spiral_read(self, grid: list, side: int) -> bytearray:
        """Read a grid in spiral order back to bytes."""
        decoded = bytearray()
        total_cells = side * side
        r, c = 0, 0
        dr, dc = 0, 1
        min_r, max_r, min_c, max_c = 0, side - 1, 0, side - 1
        
        for _ in range(total_cells):
            decoded.append(grid[r][c])
            next_r, next_c = r + dr, c + dc
            if not (min_r <= next_r <= max_r and min_c <= next_c <= max_c):
                dr, dc = dc, -dr
                if dr == 1:
                    min_r += 1
                elif dc == -1:
                    max_c -= 1
                elif dr == -1:
                    max_r -= 1
                elif dc == 1:
                    min_c += 1
                next_r, next_c = r + dr, c + dc
            r, c = next_r, next_c
        return decoded

    def encode(self, text: str, ecc_symbols: int = None) -> str:
        if not text:
            return ""
        if ecc_symbols is None:
            ecc_symbols = self.ecc_symbols
        
        data = text.encode('utf-8')
        
        # Apply ECC if enabled
        if ecc_symbols > 0:
            data = ErrorCorrection.encode(data, ecc_symbols)
        
        length = len(data)
        side = math.ceil(math.sqrt(length))
        grid = self._spiral_fill(data, side)
        
        return "\n".join("".join(chr(self.BASE + val) for val in row) for row in grid)

    def decode(self, text: str, ecc_symbols: int = None) -> str:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return ""
        
        side = len(lines)
        grid = [[0] * side for _ in range(side)]
        
        for r in range(side):
            for c in range(min(side, len(lines[r]))):
                val = ord(lines[r][c]) - self.BASE
                if val < 0 or val > 255:
                    val = 0
                grid[r][c] = val
        
        decoded = self._spiral_read(grid, side)
        
        # Strip trailing zeros (padding)
        while decoded and decoded[-1] == 0:
            decoded.pop()
        
        if not decoded:
            return ""
        
        # Attempt ECC decode (auto-detects from magic byte)
        decoded_data, had_ecc, errors = ErrorCorrection.decode(bytes(decoded), ecc_symbols)
        
        if errors > 0:
            log_info(f"Corrected {errors} error(s) using Reed-Solomon.")
        elif errors < 0:
            log_warn("Data corruption detected but could not be repaired.")
        
        try:
            return decoded_data.decode('utf-8')
        except Exception:
            return f"[Raw Data]: {decoded_data.hex()}"

# ==========================================
#  CLI LOGIC
# ==========================================

def list_ciphers():
    """Print all available ciphers and exit."""
    print("\nAvailable Ciphers:")
    print("=" * 60)
    for name, cipher in CIPHER_REGISTRY.items():
        ecc_support = "✓ ECC" if hasattr(cipher, 'ecc_symbols') else "  ---"
        print(f"  {name:<12} [{ecc_support}]  {cipher.description}")
    print("=" * 60)
    print(f"\nTotal: {len(CIPHER_REGISTRY)} cipher(s) registered.")


def main():
    global VERBOSE
    
    # Preliminary scan for --verbose (needed before plugin loading)
    VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv
    
    # Load plugins before parsing args (so they appear in --list and -m choices)
    # We'll do a preliminary scan for --plugin-dir
    plugin_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--plugin-dir" and i + 1 < len(sys.argv):
            plugin_dir = sys.argv[i + 1]
            break
        elif arg.startswith("--plugin-dir="):
            plugin_dir = arg.split("=", 1)[1]
            break
    
    loaded_plugins = load_plugins(plugin_dir)
    if loaded_plugins:
        log_info(f"Loaded plugins: {', '.join(loaded_plugins)}")
    
    parser = argparse.ArgumentParser(
        description="UN7X Braille Cipher Suite v4.0 (Auto-Detect + ECC + Plugins)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--version", action="version", version="%(prog)s 4.0")

    method_help = "\n".join(f"  {k:<12}: {v.description}" for k, v in CIPHER_REGISTRY.items())
    
    # Method selection (choices are dynamic based on loaded plugins)
    parser.add_argument("-m", "--method", choices=list(CIPHER_REGISTRY.keys()), default="int2",
                        help=f"Select cipher algorithm (default: int2). Auto-detected on decode.\n{method_help}")

    # Main action group
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-e", "--encode", action="store_true", help="Encode mode")
    action_group.add_argument("-d", "--decode", action="store_true", help="Decode mode")
    action_group.add_argument("-l", "--list", action="store_true", help="List all available ciphers")
    
    # ECC options
    parser.add_argument("--ecc-symbols", type=int, default=DEFAULT_ECC_SYMBOLS, metavar="N",
                        help=f"Reed-Solomon ECC symbols (default: {DEFAULT_ECC_SYMBOLS}). Higher = more error correction.")
    parser.add_argument("--no-ecc", action="store_true",
                        help="Disable error correction (equivalent to --ecc-symbols 0)")
    
    # Plugin directory
    parser.add_argument("--plugin-dir", type=str, metavar="PATH",
                        help="Custom plugin directory (must contain manifest.json)")
    
    # Verbose output
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output (info and warning messages)")
    
    # I/O options
    io_group = parser.add_mutually_exclusive_group()
    io_group.add_argument("-t", "--text", help="Direct text input")
    io_group.add_argument("-i", "--input", help="Input file path")

    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()
    
    # Handle --list action
    if args.list:
        list_ciphers()
        sys.exit(0)
    
    # Resolve ECC symbols (--no-ecc takes precedence)
    ecc_symbols = 0 if args.no_ecc else args.ecc_symbols

    # 1. READ INPUT
    source_text = ""
    if args.text:
        source_text = args.text
    elif args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                source_text = f.read()
        except FileNotFoundError:
            sys.exit(f"Error: File '{args.input}' not found.")
    elif not sys.stdin.isatty():
        source_text = sys.stdin.read()
    else:
        print(f"[CIPHER] Paste input below. Ctrl+D (Unix) or Ctrl+Z (Win) to end:")
        try:
            source_text = sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(0)

    # 2. SELECT CIPHER & PRE-PROCESS
    result = ""

    if args.encode:
        # Encode Mode
        method_name = args.method
        cipher = CIPHER_REGISTRY[method_name]
        
        try:
            # Pass ECC symbols to ciphers that support it
            if hasattr(cipher, 'ecc_symbols'):
                encoded_body = cipher.encode(source_text, ecc_symbols=ecc_symbols)
            else:
                if ecc_symbols > 0:
                    log_warn(f"Cipher '{method_name}' does not support ECC. Encoding without error correction.")
                encoded_body = cipher.encode(source_text)
            # Inject Watermark
            result = WatermarkEngine.inject(encoded_body, method_name)
        except Exception as e:
            sys.exit(f"Encode Error: {e}")

    else:
        # Decode Mode: Attempt Auto-Detection
        detected_method, clean_text = WatermarkEngine.detect(source_text)
        
        if detected_method and detected_method in CIPHER_REGISTRY:
            if args.method and args.method != "int2" and args.method != detected_method:
                 # Only warn if user explicitly chose something different from default and detection
                log_warn(f"User specified '{args.method}' but invisible watermark says '{detected_method}'. Using detected method.")
            cipher = CIPHER_REGISTRY[detected_method]
        else:
            # Fallback
            target_method = args.method
            cipher = CIPHER_REGISTRY[target_method]
            clean_text = source_text

        if cipher.name == 'square':
            clean_text = clean_text.strip('\r')
        elif cipher.name == 'integer':
            clean_text = clean_text.strip()
            
        try:
            # Pass ECC symbols to ciphers that support it (auto-detect from magic byte)
            if hasattr(cipher, 'ecc_symbols'):
                result = cipher.decode(clean_text, ecc_symbols=ecc_symbols)
            else:
                result = cipher.decode(clean_text)
        except Exception as e:
            sys.exit(f"Decode Error ({cipher.name}): {e}")

    # 3. WRITE OUTPUT
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(result)
                if args.decode: f.write("\n")
        except OSError as e:
            sys.exit(f"Error writing output: {e}")
    else:
        print(result)

if __name__ == "__main__":
    main()
