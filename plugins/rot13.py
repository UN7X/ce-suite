"""
ROT13 Cipher Plugin - Example for the Cipher Engine Plugin System

This file demonstrates how to create a custom cipher plugin.
To create your own cipher:

1. Create a new .py file in the plugins/ directory
2. Import the required base class and decorator (they're injected automatically)
3. Create a class extending CipherStrategy
4. Use the @register_cipher decorator
5. Add an entry to manifest.json with the file name and cipher name

The CipherStrategy and register_cipher are automatically made available
when this module is loaded by the plugin system.
"""

# These are injected by the plugin loader - no explicit import needed
# from cipher_engine import CipherStrategy, register_cipher


@register_cipher
class Rot13Cipher(CipherStrategy):
    """
    ROT13 substitution cipher.
    
    A simple letter substitution that replaces each letter with
    the letter 13 positions after it in the alphabet.
    ROT13 is its own inverse: encode and decode are the same operation.
    """
    
    name = "rot13"
    description = "Simple ROT13 letter substitution cipher (example plugin)."
    
    def _rot13(self, text: str) -> str:
        """Apply ROT13 transformation to text."""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def encode(self, text: str) -> str:
        """Encode text using ROT13."""
        return self._rot13(text)
    
    def decode(self, text: str) -> str:
        """Decode ROT13 text (same as encode since ROT13 is symmetric)."""
        return self._rot13(text)
