#!/usr/bin/env python3

import argparse
import sys
import json
import urllib.parse
import base64
import re
from urllib.parse import urlparse, parse_qsl


# =========================
# COLORS
# =========================
class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# =========================
# MAIN CLASS
# =========================
class URLFormatter:

    SENSITIVE_PARAMS = {
        'redirect_uri', 'state', 'code', 'next', 'return',
        'url', 'callback', 'redirect', 'token', 'access_token'
    }

    def __init__(self, use_color=True, enable_user_detection=True, max_depth=5):
        self.use_color = use_color
        self.enable_user_detection = enable_user_detection
        self.max_depth = max_depth

    def is_meaningful_text(self, text):
        if not text:
            return False

        # remove whitespace
        stripped = text.strip()

        # too short → ignore
        if len(stripped) < 3:
            return False

        # check printable ratio
        printable = sum(c.isprintable() for c in stripped)
        ratio = printable / len(stripped)

        return ratio > 0.9
    # =========================
    # COLOR
    # =========================
    def color(self, text, color, bold=False):
        if not self.use_color:
            return text
        return f"{Colors.BOLD if bold else ''}{color}{text}{Colors.END}"

    # =========================
    # VALID URL CHECK
    # =========================
    def is_valid_url(self, s):
        return s.startswith("http://") or s.startswith("https://")

    # =========================
    # URL DECODING
    # =========================
    def decode_url(self, value):
        current = value
        layers = 0

        for _ in range(self.max_depth):
            try:
                decoded = urllib.parse.unquote(current)
            except Exception:
                break

            if decoded == current:
                break

            current = decoded
            layers += 1

        return current, layers
    # =========================
    # Base64 decoding 
    # =========================

    def is_base64(self, value):
        try:
            v = value.replace('-', '+').replace('_', '/')
            v += '=' * (-len(v) % 4)
            decoded = base64.b64decode(v, validate=True)
            return True
        except Exception:
            return False

    def decode_base64(self, value):
        try:
            v = value.replace('-', '+').replace('_', '/')
            v += '=' * (-len(v) % 4)
            return base64.b64decode(v).decode(errors="ignore")
        except Exception:
            return None

    # =========================
    # USER DETECTION
    # =========================
    def find_users(self, value, key=None):
        users = []

        # email
        for e in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value):
            users.append(("email", e))

        # username (only if param suggests)
        if key and key.lower() in ['user', 'username', 'login']:
            if re.fullmatch(r'[a-zA-Z0-9_.-]{3,}', value):
                users.append(("username", value))

        # JWT
        jwt = re.search(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', value)
        if jwt:
            users.append(("jwt", jwt.group()))

        return users

        # =========================
        # Fragment section
        # =========================
    def parse_fragment(self, fragment):
        if not fragment:
            return None, []

        # key=value style
        if "=" in fragment:
            parts = fragment.split("&")
            result = []

            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                else:
                    k, v = part, ""
                result.append((k, v))

            return None, result
        # raw fragment
        return fragment, []
    # =========================
    # ANALYSIS
    # =========================
    def analyze(self, key, value):
        result = {
            "original": value,
            "decoded": None,
            "layers": 0,
            "double_encoding": False,
            "base64": None,
            "json": None,
            "users": [],
            "warnings": []
        }

        # URL decode
        decoded, layers = self.decode_url(value)
        result["layers"] = layers
        result["decoded"] = decoded if decoded != value else None

        if layers >= 2:
            result["double_encoding"] = True
            result["warnings"].append(f"Double encoding ({layers} layers)")

        # Try JSON
        def try_json(val):
            try:
                return json.loads(val)
            except:
                return None

        j = try_json(decoded)

        # Base64 → JSON chain
        if not j and self.is_base64(decoded):
            b = self.decode_base64(decoded)

            if b:
                b = b.strip()

            if b and b != decoded and self.is_meaningful_text(b):
                result["base64"] = b

                j2 = try_json(b)
                if isinstance(j2, (dict, list)):
                    result["json"] = j2

        if isinstance(j, (dict, list)):
            result["json"] = j

        # Users
        if self.enable_user_detection:
            users = []
            users.extend(self.find_users(value, key))
            users.extend(self.find_users(decoded, key))

            seen = set()
            clean = []
            for t, u in users:
                if u not in seen:
                    seen.add(u)
                    clean.append((t, u))

            result["users"] = clean

        # Warnings
        if key.lower() in self.SENSITIVE_PARAMS:
            result["warnings"].append("Sensitive parameter")

        if decoded.startswith(("http://", "https://", "//")):
            result["warnings"].append("Possible open redirect")

        return result

    # =========================
    # PRINT MODE
    # =========================
    def print_url(self, url):
        lines = []

        try:
            parsed = urlparse(url)
        except Exception as e:
            return self.color(f"[Error] Invalid URL: {e}", Colors.RED)

        # Host + decoding
        decoded_host, layers = self.decode_url(parsed.netloc)

        lines.append(self.color("=" * 60, Colors.CYAN))
        lines.append(self.color("  [TARGET]", Colors.BLUE, True) + " " + self.color(f"{parsed.scheme}://{parsed.netloc}", Colors.WHITE, True))

        if layers:
            lines.append(f"  {self.color('[host decoded]', Colors.CYAN)} = {decoded_host}")

        # Username + domain extraction
        if "@" in decoded_host:
            user_part, domain_part = decoded_host.split("@", 1)
            lines.append(f"  {self.color('[username]', Colors.CYAN)} {user_part}")
            lines.append(f"  {self.color('[domain]', Colors.CYAN)} {domain_part}")
        else:
            lines.append(f"  {self.color('[domain]', Colors.CYAN)} {decoded_host}")

        # Path
        if parsed.path:
            lines.append(f"  {self.color('[path]',Colors.BLUE)} {self.color(parsed.path, Colors.WHITE)}")

        params = parse_qsl(parsed.query, keep_blank_values=True)

        if params:
            lines.append(self.color("\n  Query Params:", Colors.YELLOW, True))
        
        for k, v in params:
            key_color = Colors.RED if k.lower() in self.SENSITIVE_PARAMS else Colors.YELLOW
            lines.append(f"     {self.color(k, key_color)} = {self.color(v, Colors.GREEN)}")

            analysis = self.analyze(k, v)

            if analysis["layers"]:
                layer_text = f"[decoded x{analysis['layers']}]"
                lines.append(f"    {self.color(layer_text, Colors.CYAN)}")

            if analysis["decoded"]:
                lines.append(f"    {self.color('[decoded]', Colors.CYAN)} = {analysis['decoded']}")

            if analysis["base64"]:
                lines.append(f"    {self.color('[base64]', Colors.CYAN)} = {analysis['base64']}")

            if analysis["json"]:
                lines.append(f"    {self.color('[json]', Colors.CYAN)}:")
                pretty_json = json.dumps(analysis["json"], indent=4)
                for line in pretty_json.splitlines():
                    lines.append(f"      {line}")

            for t, u in analysis["users"]:
                lines.append(f"    {self.color('[user]', Colors.CYAN)} {t}: {u}")

            for w in analysis["warnings"]:
                lines.append(f"    {self.color('[!]', Colors.RED)} {w}")
        # =========================
        # FRAGMENT
        # =========================
        raw_fragment, frag_params = self.parse_fragment(parsed.fragment)

        if parsed.fragment:
            lines.append(self.color("\n  Fragment:", Colors.YELLOW, True))

            if frag_params:
                for k, v in frag_params:
                    lines.append(f"     {self.color(k, Colors.YELLOW)} = {self.color(v, Colors.GREEN)}")

                    analysis = self.analyze(k, v)

                    if analysis["decoded"]:
                        lines.append(f"    {self.color('[decoded]', Colors.CYAN)} = {analysis['decoded']}")

                    if analysis["base64"]:
                        lines.append(f"    {self.color('[base64]', Colors.CYAN)} = {analysis['base64']}")

                    for w in analysis["warnings"]:
                        lines.append(f"    {self.color('[!]', Colors.RED)} {w}")
            else:
                lines.append(f"  {self.color('[raw]', Colors.CYAN)} {raw_fragment}")
        lines.append(f"\n  {self.color('Url:', Colors.YELLOW)} {self.color(url, Colors.GREEN)}")
        return "\n".join(lines)

    def write_output(text, file=None):
        if file:
            try:
                with open(file, "a") as f:
                    f.write(text + "\n")
            except Exception as e:
                print(f"[Error] Cannot write to file: {e}")
        else:
            print(text)


    def color_json(self, data):
        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        if not self.use_color:
            return json_str

        # Color rules
        json_str = re.sub(r'\"(.*?)\":', 
            lambda m: f'{self.color(f"{m.group(1)}", Colors.BLUE, True)}:', json_str)

        json_str = re.sub(r': \"(.*?)\"', 
            lambda m: f': {self.color(f"\"{m.group(1)}\"", Colors.GREEN)}', json_str)

        json_str = re.sub(r': (\d+)', 
            lambda m: f': {self.color(m.group(1), Colors.CYAN)}', json_str)

        json_str = re.sub(r': (true|false|null)', 
            lambda m: f': {self.color(m.group(1), Colors.RED)}', json_str)

        return json_str
    # =========================
    # JSON OUTPUT
    # =========================
    def to_json(self, url):
        parsed = urlparse(url)

        # Decode host
        
        decoded_host, _ = self.decode_url(parsed.netloc)
        
        # Extract username + domain
        username = None
        domain = parsed.netloc

        if "@" in decoded_host:
            username, domain = decoded_host.split("@", 1)
        else:
            domain = decoded_host

        result = {}

        # 1. host
        result["host"] = parsed.netloc

        # 2. decoded_host (if exists)
        if decoded_host != parsed.netloc:
            result["decoded_host"] = decoded_host

        # 3. username (if exists)
        if username is not None:
            result["username"] = username

        # 4. domain
        result["domain"] = domain

        # 5. rest
        result["path"] = parsed.path
        result["params"] = {}
        if(parsed.fragment != ''):
            result["fragment"] = {}
        result["url"] = url

        if(decoded_host != parsed.netloc):
            result["decoded_host"] = decoded_host
        if(username != None):
            result["username"] = username

        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            analysis = self.analyze(k, v)

            if not analysis["warnings"] and not analysis["base64"]:
                result["params"][k] = v
            else:
                param_obj = {"value": v}

                if analysis["base64"]:
                    param_obj["base64"] = analysis["base64"]

                if analysis["warnings"]:
                    param_obj["warnings"] = analysis["warnings"]

                result["params"][k] = param_obj


           # =========================
            # FRAGMENT
            # =========================
        raw_fragment, frag_params = self.parse_fragment(parsed.fragment)

        if parsed.fragment:
            if frag_params:
                for k, v in frag_params:
                    analysis = self.analyze(k, v)

                    if not analysis["warnings"] and not analysis["base64"]:
                        result["fragment"][k] = v
                    else:
                        obj = {"value": v}

                        if analysis["base64"]:
                            obj["base64"] = analysis["base64"]

                        if analysis["warnings"]:
                            obj["warnings"] = analysis["warnings"]

                        result["fragment"][k] = obj
            else:
                result["fragment"]["raw"] = raw_fragment
        return "\n" + self.color_json(result)


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="Advanced URL Analyzer")
    parser.add_argument("url", nargs="?", help="URL input")
    parser.add_argument("-j", "--json", action="store_true", help="Show json format")
    parser.add_argument("-nc", "--no-color", action="store_true", help="No Color output")
    parser.add_argument("-o", "--output", help="Save output to file")

    args = parser.parse_args()

    tool = URLFormatter(use_color=not args.no_color)

    urls = []

    # =========================
    # INPUT HANDLING
    # =========================
    if not args.url and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            decoded, _ = tool.decode_url(line)

            # ALWAYS try decoded first
            if decoded.startswith(("http://", "https://")):
                urls.append(decoded)
            elif line.startswith(("http://", "https://")):
                urls.append(line)
    else:
        if args.url:
            decoded, _ = tool.decode_url(args.url)
            if decoded.startswith(("http://", "https://")):
                urls.append(decoded)
            else:
                urls.append(args.url)

    # 🚨 SAFETY CHECK (THIS FIXES YOUR CRASH)
    if not urls:
        print("[Error] No valid URL found")
        return

    # =========================
    # PROCESSING
    # =========================
    for url in urls:

        if args.output:
            # disable color for file
            original_color = tool.use_color
            tool.use_color = False

            result = tool.to_json(url) if args.json else tool.print_url(url)

            tool.use_color = original_color

            try:
                with open(args.output, "a") as f:
                    f.write(result + "\n\n")
            except Exception as e:
                print(f"[Error] {e}")
        else:
            result = tool.to_json(url) if args.json else tool.print_url(url)
            print(result + "\n")

if __name__ == "__main__":
    main()
