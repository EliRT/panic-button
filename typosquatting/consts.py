import os

TOP_ALEXA_URLS = open(os.path.abspath("../assets/alexa_top_200.csv"))

KEYBOARD_ADJACENT_CHARS_MAPPING = {
    'a': ['a', 's'],
    'b': ['b', 'v', 'n', 'g', 'h'],
    'c': ['c', 'x', 'v', 'd', 'f'],
    'd': ['d', 's', 'f', 'e', 'c'],
    'e': ['e', 'w', 'r', 'd'],
    'f': ['f', 'd', 'g', 'r', 'v'],
    'g': ['g', 'f', 'h', 't', 'v', 'b'],
    'h': ['h', 'g', 'j', 'y', 'n', 'b'],
    'i': ['i', 'u', 'o', 'k'],
    'j': ['j', 'h', 'k', 'u'],
    'k': ['k', 'j', 'l', 'i'],
    'l': ['l', 'k', 'o', 'p'],
    'm': ['m', 'n'],
    'n': ['n', 'm', 'b'],
    'o': ['o', 'p', 'i', 'l'],
    'p': ['p', 'o'],
    'q': ['q', 'w', 'a'],
    'r': ['r', 'e', 't', 'f'],
    's': ['s', 'a', 'd', 'w', 'z', 'x'],
    't': ['t', 'r', 'y', 'g'],
    'u': ['u', 'y', 'i', 'j'],
    'v': ['v', 'c', 'b', 'f', 'g'],
    'w': ['w', 'q', 'e', 's'],
    'x': ['x', 'z', 'c', 's', 'd'],
    'y': ['y', 't', 'u', 'h'],
    'z': ['z', 'x', 's', 'a'],
}
