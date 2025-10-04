// Content Data Structure
const contentData = {
    crypto: {
        title: "Cryptography",
        sections: [
            {
                id: 'crypto-basics',
                title: 'Basics & Identification',
                items: [
                    {
                        title: 'Encoding vs Encryption vs Hashing',
                        content: `**Encoding**: Reversible, no key (Base64, Hex, URL)
**Encryption**: Reversible with key (AES, RSA, XOR)
**Hashing**: One-way function (MD5, SHA-1, SHA-256)`,
                        commands: []
                    },
                    {
                        title: 'Hash Identification',
                        content: `MD5: 32 hex characters
SHA-1: 40 hex characters
SHA-256: 64 hex characters
SHA-512: 128 hex characters`,
                        commands: ['hashid <hash>', 'hash-identifier']
                    },
                    {
                        title: 'Quick Recognition Patterns',
                        content: `Base64: A-Za-z0-9+/= (ends with = or ==)
Hex: Only 0-9 a-f
Binary: Only 0 and 1
Caesar/ROT13: All uppercase letters
Morse: Dots and dashes (. -)`,
                        commands: []
                    }
                ]
            },
            {
                id: 'crypto-encoding',
                title: 'Common Encodings',
                items: [
                    {
                        title: 'Base64',
                        content: 'Most common encoding in CTF. Recognizable by A-Za-z0-9+/= characters',
                        commands: [
                            'echo "SGVsbG8=" | base64 -d',
                            'base64 -d file.txt',
                            'python3 -c "import base64; print(base64.b64decode(b\'SGVsbG8=\'))"'
                        ]
                    },
                    {
                        title: 'Hexadecimal',
                        content: 'Only uses characters 0-9 and a-f. Each byte = 2 hex digits',
                        commands: [
                            'echo "48656c6c6f" | xxd -r -p',
                            'xxd -r -p file.hex',
                            'python3 -c "print(bytes.fromhex(\'48656c6c6f\'))"'
                        ]
                    },
                    {
                        title: 'Binary',
                        content: 'Only 1s and 0s. Usually 8 bits per character',
                        commands: [
                            'python3 -c "print(chr(int(\'01001000\', 2)))"'
                        ]
                    },
                    {
                        title: 'URL Encoding',
                        content: 'Special characters as %XX (hex). Space = %20',
                        commands: [
                            'python3 -c "from urllib.parse import unquote; print(unquote(\'Hello%20World\'))"'
                        ]
                    }
                ]
            },
            {
                id: 'crypto-classical',
                title: 'Classical Ciphers',
                items: [
                    {
                        title: 'Caesar Cipher / ROT13',
                        content: 'Shifts alphabet by N positions. ROT13 = shift by 13',
                        commands: [
                            'echo "KHOOR" | tr \'A-Za-z\' \'N-ZA-Mn-za-m\'  # ROT13',
                            '# Online: dcode.fr/caesar-cipher'
                        ]
                    },
                    {
                        title: 'Substitution Cipher',
                        content: 'Each letter mapped to another. Use frequency analysis (E, T, A, O, I, N most common)',
                        commands: ['# Online: quipqiup.com', '# Tool: dcode.fr/monoalphabetic-substitution']
                    },
                    {
                        title: 'Vigenère Cipher',
                        content: 'Uses repeating keyword. Find key length then break each shift',
                        commands: ['# Online: dcode.fr/vigenere-cipher', '# Auto-break available on dcode.fr']
                    },
                    {
                        title: 'Atbash Cipher',
                        content: 'Reverse alphabet: A↔Z, B↔Y, C↔X...',
                        commands: ['# Online: dcode.fr/atbash-cipher']
                    }
                ]
            },
            {
                id: 'crypto-hashing',
                title: 'Hash Cracking',
                items: [
                    {
                        title: 'Online Hash Lookup',
                        content: 'Try these first - fastest method for common passwords',
                        commands: [
                            '# Websites:',
                            '# crackstation.net',
                            '# hashes.com',
                            '# md5decrypt.net'
                        ]
                    },
                    {
                        title: 'John the Ripper',
                        content: 'CPU-based hash cracker. Good for most hash types',
                        commands: [
                            'john --format=raw-md5 hash.txt --wordlist=rockyou.txt',
                            'john --format=raw-sha1 hash.txt --wordlist=rockyou.txt',
                            'john --format=raw-sha256 hash.txt --wordlist=rockyou.txt',
                            'john --show hash.txt  # Show cracked passwords'
                        ]
                    },
                    {
                        title: 'Hashcat',
                        content: 'GPU-accelerated. Much faster for large wordlists',
                        commands: [
                            'hashcat -m 0 hash.txt rockyou.txt     # MD5',
                            'hashcat -m 100 hash.txt rockyou.txt   # SHA-1',
                            'hashcat -m 1400 hash.txt rockyou.txt  # SHA-256',
                            'hashcat -m 1800 hash.txt rockyou.txt  # SHA-512'
                        ]
                    }
                ]
            },
            {
                id: 'crypto-xor',
                title: 'XOR Cipher',
                items: [
                    {
                        title: 'Single-Byte XOR',
                        content: 'Try all 256 possible keys. Look for readable text',
                        commands: [
                            'python3 -c "cipher=bytes.fromhex(\'1c0e1c0a\'); [print(f\'Key {k}: {\"\".join(chr(b^k) for b in cipher)}\') for k in range(256)]"'
                        ]
                    },
                    {
                        title: 'Multi-Byte XOR (Repeating Key)',
                        content: 'If you know part of plaintext, recover the key by XORing known plaintext with ciphertext',
                        commands: [
                            '# If plaintext starts with "FLAG{"',
                            'python3 -c "known=b\'FLAG{\'; cipher=bytes.fromhex(\'...\'); print(bytes(a^b for a,b in zip(known,cipher)))"'
                        ]
                    },
                    {
                        title: 'XOR Properties',
                        content: `A ⊕ B = C
C ⊕ B = A (reversible!)
A ⊕ A = 0
A ⊕ 0 = A`,
                        commands: []
                    }
                ]
            },
            {
                id: 'crypto-rsa',
                title: 'RSA Attacks',
                items: [
                    {
                        title: 'Small e Attack (e=3)',
                        content: 'If m³ < n, just take cube root',
                        commands: [
                            'python3 -c "import gmpy2; c=12345; m=gmpy2.iroot(c,3)[0]; print(bytes.fromhex(hex(m)[2:]))"'
                        ]
                    },
                    {
                        title: 'Factor n (Small modulus)',
                        content: 'Check factordb.com first, then try factoring',
                        commands: [
                            '# Check: factordb.com/index.php?query=<n>',
                            'python3 -c "import primefac; print(list(primefac.primefac(123456789)))"'
                        ]
                    },
                    {
                        title: 'RsaCtfTool (Automated)',
                        content: 'Tries multiple RSA attacks automatically',
                        commands: [
                            'git clone https://github.com/RsaCtfTool/RsaCtfTool.git',
                            'cd RsaCtfTool && pip3 install -r requirements.txt',
                            'python3 RsaCtfTool.py --publickey key.pem --uncipherfile encrypted.txt'
                        ]
                    },
                    {
                        title: 'Wiener\'s Attack (Small d)',
                        content: 'When private exponent d is small',
                        commands: [
                            'pip3 install owiener',
                            'python3 -c "import owiener; d=owiener.attack(e, n); print(d)"'
                        ]
                    }
                ]
            },
            {
                id: 'crypto-aes',
                title: 'AES & Symmetric Crypto',
                items: [
                    {
                        title: 'AES Decryption (with key)',
                        content: 'Need key (16/24/32 bytes) and often IV (16 bytes)',
                        commands: [
                            'from Crypto.Cipher import AES',
                            'from Crypto.Util.Padding import unpad',
                            'import base64',
                            '',
                            'key = b"SIXTEEN_BYTE_KEY"',
                            'iv = b"SIXTEEN_BYTE_IV!"',
                            'ct = base64.b64decode("...")',
                            '',
                            'cipher = AES.new(key, AES.MODE_CBC, iv)',
                            'pt = unpad(cipher.decrypt(ct), 16)',
                            'print(pt)'
                        ]
                    },
                    {
                        title: 'ECB Mode Detection',
                        content: 'Look for repeated blocks (same plaintext = same ciphertext)',
                        commands: [
                            '# If blocks repeat, it\'s likely ECB mode',
                            '# Can do cut-and-paste attacks'
                        ]
                    }
                ]
            },
            {
                id: 'crypto-tools',
                title: 'Essential Tools',
                items: [
                    {
                        title: 'CyberChef',
                        content: 'THE Swiss Army knife for crypto. Try "Magic" operation for auto-detection',
                        commands: ['# URL: gchq.github.io/CyberChef/']
                    },
                    {
                        title: 'dcode.fr',
                        content: 'Best for classical ciphers. Has cipher identifier',
                        commands: ['# URL: dcode.fr']
                    },
                    {
                        title: 'CrackStation',
                        content: 'Instant hash lookup. Try this FIRST for hashes',
                        commands: ['# URL: crackstation.net']
                    },
                    {
                        title: 'FactorDB',
                        content: 'Database of factored numbers. Essential for RSA',
                        commands: ['# URL: factordb.com']
                    }
                ]
            }
        ]
    },
    stego: {
        title: "Steganography",
        sections: [
            {
                id: 'stego-basics',
                title: 'Initial Analysis (ALWAYS START HERE)',
                items: [
                    {
                        title: 'Basic File Information',
                        content: 'Check file type, size, and basic properties',
                        commands: [
                            'file image.png',
                            'ls -lh image.png',
                            'xxd image.png | head -20  # View hex'
                        ]
                    },
                    {
                        title: 'Extract Strings',
                        content: 'Find readable text in any file. Often contains flags!',
                        commands: [
                            'strings image.png',
                            'strings image.png | grep -i flag',
                            'strings -e l image.png  # 16-bit little-endian',
                            'strings -e b image.png  # 16-bit big-endian'
                        ]
                    },
                    {
                        title: 'File Signatures (Magic Bytes)',
                        content: `PNG: 89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF
GIF: 47 49 46 38
ZIP: 50 4B 03 04
PDF: 25 50 44 46`,
                        commands: ['xxd image.png | head -n 1  # Check first bytes']
                    },
                    {
                        title: 'Metadata Extraction',
                        content: 'EXIF data can hide flags in comments, descriptions, etc.',
                        commands: [
                            'exiftool image.jpg',
                            'exiftool image.jpg | grep -i flag',
                            'exiftool -Comment image.jpg'
                        ]
                    }
                ]
            },
            {
                id: 'stego-images',
                title: 'Image Steganography',
                items: [
                    {
                        title: 'zsteg (PNG/BMP - TRY FIRST!)',
                        content: 'Automatic LSB detection. Often finds flag immediately',
                        commands: [
                            'zsteg image.png',
                            'zsteg -a image.png  # All methods',
                            'zsteg -E "b1,rgb,lsb" image.png > output.txt'
                        ]
                    },
                    {
                        title: 'steghide (JPEG/BMP/WAV/AU)',
                        content: 'Extract embedded files. Try empty password first',
                        commands: [
                            'steghide info image.jpg',
                            'steghide extract -sf image.jpg',
                            'steghide extract -sf image.jpg -p password123'
                        ]
                    },
                    {
                        title: 'stegcracker (Brute Force steghide)',
                        content: 'Brute force steghide passwords',
                        commands: [
                            'stegcracker image.jpg /usr/share/wordlists/rockyou.txt',
                            'stegcracker image.jpg custom_wordlist.txt'
                        ]
                    },
                    {
                        title: 'Stegsolve (GUI - Visual Analysis)',
                        content: 'Cycle through color planes and bit planes. Look for QR codes, text, patterns',
                        commands: [
                            'java -jar Stegsolve.jar',
                            '# Click arrows to cycle through planes',
                            '# Analyse > Data Extract to save binary data'
                        ]
                    },
                    {
                        title: 'binwalk (Find Embedded Files)',
                        content: 'Detects files hidden inside images (ZIP in PNG, etc.)',
                        commands: [
                            'binwalk image.png',
                            'binwalk -e image.png  # Extract all',
                            'binwalk --dd=".*" image.png'
                        ]
                    },
                    {
                        title: 'foremost (File Carving)',
                        content: 'Extracts files based on headers/footers',
                        commands: [
                            'foremost -i image.png -o output/',
                            'ls output/  # Check jpg/, png/, zip/ folders'
                        ]
                    }
                ]
            },
            {
                id: 'stego-lsb',
                title: 'LSB (Least Significant Bit)',
                items: [
                    {
                        title: 'What is LSB?',
                        content: `Data hidden in least significant bits of pixels
Red: 11001010 → 11001011 (changed last bit)
Invisible to human eye!`,
                        commands: []
                    },
                    {
                        title: 'Extract LSB with Python',
                        content: 'Extract LSB manually if tools fail',
                        commands: [
                            'from PIL import Image',
                            'img = Image.open("image.png")',
                            'pixels = list(img.getdata())',
                            '',
                            'binary = ""',
                            'for pixel in pixels:',
                            '    r, g, b = pixel',
                            '    binary += str(r & 1)',
                            '    binary += str(g & 1)',
                            '    binary += str(b & 1)',
                            '',
                            'message = ""',
                            'for i in range(0, len(binary), 8):',
                            '    byte = binary[i:i+8]',
                            '    if len(byte) == 8:',
                            '        message += chr(int(byte, 2))',
                            'print(message)'
                        ]
                    }
                ]
            },
            {
                id: 'stego-audio',
                title: 'Audio Steganography',
                items: [
                    {
                        title: 'Spectrogram Analysis',
                        content: 'Images/text hidden in frequency domain. Check with Sonic Visualizer or Audacity',
                        commands: [
                            'sonic-visualizer audio.wav',
                            '# Layer > Add Spectrogram',
                            '# Look for patterns, text, QR codes'
                        ]
                    },
                    {
                        title: 'Audacity Spectrogram',
                        content: 'Free alternative to Sonic Visualizer',
                        commands: [
                            'audacity audio.wav',
                            '# Select track > View > Spectrogram',
                            '# Adjust window size and color scheme'
                        ]
                    },
                    {
                        title: 'steghide for Audio',
                        content: 'Extract hidden files from WAV/AU',
                        commands: [
                            'steghide info audio.wav',
                            'steghide extract -sf audio.wav'
                        ]
                    },
                    {
                        title: 'DTMF Tones',
                        content: 'Phone keypad tones (0-9, *, #)',
                        commands: ['# Online: dialabc.com/sound/detect/']
                    }
                ]
            },
            {
                id: 'stego-text',
                title: 'Text Steganography',
                items: [
                    {
                        title: 'Whitespace Steganography',
                        content: 'Spaces and tabs encode binary data',
                        commands: [
                            'cat -A file.txt  # Shows tabs as ^I',
                            'stegsnow -C file.txt',
                            'stegsnow -C -p password file.txt'
                        ]
                    },
                    {
                        title: 'Zero-Width Characters',
                        content: 'Invisible Unicode characters (U+200B, U+200C, U+200D)',
                        commands: [
                            '# Online: 330k.github.io/misc_tools/unicode_steganography.html',
                            '# Or inspect character codes in Python'
                        ]
                    },
                    {
                        title: 'First/Last Letter Cipher',
                        content: 'Take first or last letter of each line/word',
                        commands: ['# Manual inspection usually needed']
                    }
                ]
            },
            {
                id: 'stego-archives',
                title: 'File/Archive Steganography',
                items: [
                    {
                        title: 'ZIP Comments',
                        content: 'Hidden data in ZIP file comments',
                        commands: [
                            'unzip -z file.zip',
                            '7z l -slt file.zip  # List with technical info'
                        ]
                    },
                    {
                        title: 'Password-Protected ZIP',
                        content: 'Brute force ZIP passwords',
                        commands: [
                            'fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u file.zip',
                            'zip2john file.zip > hash.txt',
                            'john hash.txt --wordlist=rockyou.txt'
                        ]
                    },
                    {
                        title: 'Corrupted Archives',
                        content: 'Try to repair or extract anyway',
                        commands: [
                            'zip -FF broken.zip --out fixed.zip',
                            'unzip -t file.zip  # Test',
                            'unzip file.zip  # Try extract anyway'
                        ]
                    }
                ]
            },
            {
                id: 'stego-advanced',
                title: 'Advanced Techniques',
                items: [
                    {
                        title: 'Image Transformations',
                        content: 'Rotate, flip, invert colors to reveal hidden data',
                        commands: [
                            'convert image.png -rotate 90 rotated.png',
                            'convert image.png -flip flipped.png',
                            'convert image.png -negate inverted.png'
                        ]
                    },
                    {
                        title: 'Image Difference',
                        content: 'Compare two similar images to find differences',
                        commands: [
                            'compare image1.png image2.png diff.png',
                            '# Or use Python PIL ImageChops.difference()'
                        ]
                    },
                    {
                        title: 'QR Code Detection',
                        content: 'QR codes might be in specific color channels',
                        commands: [
                            'zbarimg image.png',
                            '# If not found, try Stegsolve to isolate channels'
                        ]
                    },
                    {
                        title: 'Color Channel Separation',
                        content: 'Extract and analyze R, G, B channels separately',
                        commands: [
                            'from PIL import Image',
                            'img = Image.open("image.png")',
                            'r, g, b = img.split()',
                            'r.save("red.png")',
                            'g.save("green.png")',
                            'b.save("blue.png")'
                        ]
                    }
                ]
            },
            {
                id: 'stego-workflow',
                title: 'Complete Stego Workflow',
                items: [
                    {
                        title: 'The Checklist (Follow in Order)',
                        content: `1. file, ls -lh, xxd (basic info)
2. strings + grep flag
3. exiftool (metadata)
4. binwalk, foremost (embedded files)
5. zsteg (PNG/BMP)
6. steghide (JPEG/WAV)
7. Stegsolve (visual analysis)
8. Specialized tools based on file type`,
                        commands: []
                    }
                ]
            },
            {
                id: 'stego-tools',
                title: 'Essential Tools',
                items: [
                    {
                        title: 'Online All-in-One Tools',
                        content: 'Upload and auto-analyze',
                        commands: [
                            '# Aperi\'Solve: aperisolve.com',
                            '# StegOnline: stegonline.georgeom.net/upload',
                            '# Both run multiple tools automatically'
                        ]
                    },
                    {
                        title: 'Tool Installation',
                        content: 'Setup all stego tools',
                        commands: [
                            'sudo apt update',
                            'sudo apt install -y steghide stegsnow binwalk foremost exiftool',
                            'sudo apt install -y sonic-visualizer audacity',
                            'sudo apt install -y fcrackzip p7zip-full',
                            'gem install zsteg',
                            'pip3 install stegcracker',
                            'wget http://www.caesum.com/handbook/Stegsolve.jar'
                        ]
                    }
                ]
            }
        ]
    }
};

// Continue in next part...
// ... (previous content data continues)

// State Management
let expandedSections = {};
let searchResults = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeTabs();
    renderContent();
    setupSearch();
    setupEventListeners();
});

// Initialize Tabs
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
}

// Switch between tabs
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update content panels
    document.querySelectorAll('.content-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(tabName).classList.add('active');

    // Clear search when switching tabs
    document.getElementById('searchInput').value = '';
    hideSearchResults();
}

// Render all content
function renderContent() {
    Object.keys(contentData).forEach(tabKey => {
        const tabData = contentData[tabKey];
        const container = document.getElementById(tabKey);
        container.innerHTML = '';

        tabData.sections.forEach(section => {
            const sectionElement = createSectionElement(section, tabKey);
            container.appendChild(sectionElement);
        });
    });
}

// Create section element
function createSectionElement(section, tabKey) {
    const sectionDiv = document.createElement('div');
    sectionDiv.className = 'section';
    sectionDiv.id = section.id;

    // Section Header
    const header = document.createElement('div');
    header.className = 'section-header';
    header.innerHTML = `
        <h2 class="section-title">
            <svg class="section-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path d="M4 7h16M4 12h16M4 17h16"></path>
            </svg>
            <span>${section.title}</span>
        </h2>
        <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
    `;

    // Section Content
    const content = document.createElement('div');
    content.className = 'section-content';

    section.items.forEach(item => {
        const itemElement = createItemElement(item, section.id);
        content.appendChild(itemElement);
    });

    // Toggle functionality
    header.addEventListener('click', function() {
        const isExpanded = sectionDiv.classList.contains('expanded');
        sectionDiv.classList.toggle('expanded');
        expandedSections[section.id] = !isExpanded;
    });

    sectionDiv.appendChild(header);
    sectionDiv.appendChild(content);

    return sectionDiv;
}

// Create item element
function createItemElement(item, sectionId) {
    const itemDiv = document.createElement('div');
    itemDiv.className = 'item';

    // Item Title
    const title = document.createElement('div');
    title.className = 'item-title';
    title.innerHTML = `
        <svg class="item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
        <span>${item.title}</span>
    `;

    // Item Content
    const contentDiv = document.createElement('div');
    contentDiv.className = 'item-content';
    contentDiv.innerHTML = formatContent(item.content);

    itemDiv.appendChild(title);
    itemDiv.appendChild(contentDiv);

    // Commands
    if (item.commands && item.commands.length > 0) {
        const commandsDiv = document.createElement('div');
        commandsDiv.className = 'commands';

        item.commands.forEach((cmd, idx) => {
            const cmdWrapper = createCommandElement(cmd, `${sectionId}-${idx}`);
            commandsDiv.appendChild(cmdWrapper);
        });

        itemDiv.appendChild(commandsDiv);
    }

    return itemDiv;
}

// Create command element with copy button
function createCommandElement(command, id) {
    const wrapper = document.createElement('div');
    wrapper.className = 'command-wrapper';

    const cmdDiv = document.createElement('div');
    cmdDiv.className = 'command';
    cmdDiv.textContent = command;

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-button';
    copyBtn.setAttribute('data-command', command);
    copyBtn.innerHTML = `
        <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
    `;

    copyBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        copyToClipboard(command, copyBtn);
    });

    wrapper.appendChild(cmdDiv);
    wrapper.appendChild(copyBtn);

    return wrapper;
}

// Format content with bold and comments
function formatContent(content) {
    const lines = content.split('\n');
    let html = '';

    lines.forEach(line => {
        if (line.startsWith('**') && line.endsWith('**')) {
            // Bold text
            const text = line.replace(/\*\*/g, '');
            html += `<div class="content-bold">${escapeHtml(text)}</div>`;
        } else if (line.startsWith('#')) {
            // Comment
            html += `<div class="content-comment">${escapeHtml(line)}</div>`;
        } else if (line.trim()) {
            // Regular text
            html += `<div>${escapeHtml(line)}</div>`;
        }
    });

    return html;
}

// Copy to clipboard
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        button.classList.add('copied');
        button.innerHTML = `
            <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        `;

        setTimeout(() => {
            button.classList.remove('copied');
            button.innerHTML = `
                <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
            `;
        }, 2000);
    });
}

// Setup search functionality
function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    let debounceTimer;

    searchInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            const searchTerm = this.value.trim();
            if (searchTerm) {
                performSearch(searchTerm);
            } else {
                hideSearchResults();
            }
        }, 300);
    });
}

// Perform search
function performSearch(searchTerm) {
    const results = [];
    const term = searchTerm.toLowerCase();

    Object.keys(contentData).forEach(tabKey => {
        const tabData = contentData[tabKey];
        
        tabData.sections.forEach(section => {
            section.items.forEach(item => {
                const titleMatch = item.title.toLowerCase().includes(term);
                const contentMatch = item.content.toLowerCase().includes(term);
                const commandMatch = item.commands.some(cmd => 
                    cmd.toLowerCase().includes(term)
                );

                if (titleMatch || contentMatch || commandMatch) {
                    results.push({
                        tab: tabKey,
                        tabTitle: tabData.title,
                        sectionId: section.id,
                        sectionTitle: section.title,
                        itemTitle: item.title,
                        item: item
                    });
                }
            });
        });
    });

    displaySearchResults(results, searchTerm);
}

// Display search results
function displaySearchResults(results, searchTerm) {
    const searchResultsDiv = document.getElementById('searchResults');
    const resultsListDiv = document.getElementById('resultsList');
    const resultCountSpan = document.getElementById('resultCount');
    const quickTips = document.getElementById('quickTips');

    if (results.length === 0) {
        hideSearchResults();
        return;
    }

    // Hide quick tips when showing results
    quickTips.classList.add('hidden');

    resultCountSpan.textContent = results.length;
    resultsListDiv.innerHTML = '';

    results.forEach(result => {
        const resultItem = createResultElement(result, searchTerm);
        resultsListDiv.appendChild(resultItem);
    });

    searchResultsDiv.classList.remove('hidden');
}

// Create search result element
function createResultElement(result, searchTerm) {
    const resultDiv = document.createElement('div');
    resultDiv.className = 'result-item';

    // Breadcrumb
    const breadcrumb = document.createElement('div');
    breadcrumb.className = 'result-breadcrumb';
    breadcrumb.innerHTML = `
        <span class="result-badge">${result.tabTitle}</span>
        <svg class="breadcrumb-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
        <span class="result-section">${result.sectionTitle}</span>
    `;

    // Title
    const title = document.createElement('h3');
    title.className = 'result-title';
    title.innerHTML = highlightText(result.itemTitle, searchTerm);

    // Content
    const content = document.createElement('div');
    content.className = 'result-content';
    content.innerHTML = highlightText(formatContent(result.item.content), searchTerm);

    resultDiv.appendChild(breadcrumb);
    resultDiv.appendChild(title);
    resultDiv.appendChild(content);

    // Commands
    if (result.item.commands.length > 0) {
        const commandsDiv = document.createElement('div');
        commandsDiv.className = 'result-commands';

        result.item.commands.forEach(cmd => {
            const cmdDiv = document.createElement('div');
            cmdDiv.className = 'result-command';
            cmdDiv.innerHTML = highlightText(escapeHtml(cmd), searchTerm);
            commandsDiv.appendChild(cmdDiv);
        });

        resultDiv.appendChild(commandsDiv);
    }

    return resultDiv;
}

// Hide search results
function hideSearchResults() {
    const searchResultsDiv = document.getElementById('searchResults');
    const quickTips = document.getElementById('quickTips');
    
    searchResultsDiv.classList.add('hidden');
    quickTips.classList.remove('hidden');
}

// Highlight search term in text
function highlightText(text, searchTerm) {
    if (!searchTerm) return text;
    
    const regex = new RegExp(`(${escapeRegex(searchTerm)})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}

// Escape HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Escape regex special characters
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Setup additional event listeners
function setupEventListeners() {
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            document.getElementById('searchInput').focus();
        }
        
        // Escape to clear search
        if (e.key === 'Escape') {
            const searchInput = document.getElementById('searchInput');
            if (searchInput.value) {
                searchInput.value = '';
                hideSearchResults();
            }
        }
    });

    // Expand all sections button (optional - can be added to UI)
    window.expandAll = function() {
        document.querySelectorAll('.section').forEach(section => {
            section.classList.add('expanded');
        });
    };

    // Collapse all sections button (optional - can be added to UI)
    window.collapseAll = function() {
        document.querySelectorAll('.section').forEach(section => {
            section.classList.remove('expanded');
        });
    };
}

// Utility function to print all content (for debugging)
window.debugContent = function() {
    console.log('Content Data:', contentData);
    console.log('Expanded Sections:', expandedSections);
};
