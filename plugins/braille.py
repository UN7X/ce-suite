"""
Braille Cipher Plugin - Encodes text into Unicode Braille patterns

A visually striking cipher that converts bytes to Braille characters.
Each byte maps to one of the 256 possible Braille patterns (U+2800 to U+28FF).
This creates a compact, visually distinctive encoding that's both 
interesting to look at and efficient (1:1 byte-to-character ratio).
"""


@register_cipher
class BrailleCipher(CipherStrategy):
    """
    Braille pattern cipher using Unicode Braille block.
    
    Encodes raw bytes as Braille characters (U+2800 - U+28FF).
    Each Braille cell represents one byte, creating a visually
    distinctive dot pattern that encodes 256 possible values.
    
    The encoding process:
    1. Convert text to UTF-8 bytes
    2. Each byte (0-255) maps to a Braille character
    3. Braille base is U+2800, so byte N → chr(0x2800 + N)
    
    Visual example: "Hi" → "⡈⡩" (each letter becomes a unique dot pattern)
    """
    
    name = "braille"
    description = "Encodes text as Unicode Braille dot patterns (visually distinctive)."
    symbol = "dot.radiowaves.right"
    
    # Unicode Braille Patterns block starts at U+2800
    BRAILLE_BASE = 0x2800
    
    def encode(self, text: str) -> str:
        """
        Encode text to Braille patterns.
        
        Each byte of the UTF-8 encoded text becomes one Braille character.
        This creates a visually distinctive pattern of dots.
        """
        encoded_bytes = text.encode('utf-8')
        braille_chars = []
        
        for byte in encoded_bytes:
            # Map each byte (0-255) to a Braille pattern
            braille_char = chr(self.BRAILLE_BASE + byte)
            braille_chars.append(braille_char)
        
        return ''.join(braille_chars)
    
    def decode(self, text: str) -> str:
        """
        Decode Braille patterns back to text.
        
        Each Braille character is converted back to its byte value,
        then the bytes are decoded as UTF-8.
        """
        decoded_bytes = []
        
        for char in text:
            code_point = ord(char)
            
            # Verify it's in the Braille block
            if self.BRAILLE_BASE <= code_point <= self.BRAILLE_BASE + 255:
                byte_value = code_point - self.BRAILLE_BASE
                decoded_bytes.append(byte_value)
            else:
                # Non-Braille characters are passed through as-is
                # (allows for mixed content / whitespace preservation)
                decoded_bytes.extend(char.encode('utf-8'))
        
        return bytes(decoded_bytes).decode('utf-8')
