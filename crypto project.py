from enum import Enum, auto
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib, secrets, math, base64

class KeyState(Enum):
    NO_KEYS = auto()
    HAVE_KEYS = auto()

# ---------- RSA UTILITIES (educational – not for real security) ----------

def _is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # write n-1 as 2^r * d
    r, d = 0, n-1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def _gen_prime(bits):
    while True:
        n = secrets.randbits(bits)
        n |= 1
        n |= (1 << (bits-1))
        if _is_probable_prime(n):
            return n

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a//b) * y1

def _modinv(a, m):
    g, x, y = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def generate_keypair(bits=512):
    p = _gen_prime(bits//2)
    q = _gen_prime(bits//2)
    while p == q:
        q = _gen_prime(bits//2)
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = _modinv(e, phi)
    return n, e, d

def sign_message(message, n, d):
    h = hashlib.sha256(message.encode('utf-8')).digest()
    h_int = int.from_bytes(h, 'big')
    sig_int = pow(h_int, d, n)
    sig_bytes = sig_int.to_bytes((sig_int.bit_length()+7)//8, 'big')
    return base64.b64encode(sig_bytes).decode('ascii')

def verify_signature(message, signature_b64, n, e):
    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception:
        return False
    sig_int = int.from_bytes(sig_bytes, 'big')
    h_expected = hashlib.sha256(message.encode('utf-8')).digest()
    h_expected_int = int.from_bytes(h_expected, 'big')
    h_from_sig = pow(sig_int, e, n)
    return h_from_sig == h_expected_int

# ---------- GUI APP ----------

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature Creator & Verifier (RSA, SHA-256)")
        self.root.geometry("900x650")
        self.root.configure(bg="#20232a")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#20232a")
        style.configure("TLabel", background="#20232a", foreground="#ffffff")
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Small.TLabel", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.map("TButton",
                  foreground=[("disabled", "#777777")],
                  background=[("active", "#61dafb")])

        self.state = KeyState.NO_KEYS
        self.n = None
        self.e = None
        self.d = None

        top_frame = ttk.Frame(root)
        top_frame.pack(fill="x", pady=10, padx=10)

        header = ttk.Label(top_frame, text="Digital Signature Creator & Verifier",
                           style="Header.TLabel")
        header.pack(anchor="w")

        subtitle = ttk.Label(
            top_frame,
            text="Educational RSA + SHA-256 demo in Python. Generates keys, signs messages, and verifies signatures.",
            style="Small.TLabel"
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.keys_frame = ttk.Frame(notebook)
        self.sign_frame = ttk.Frame(notebook)
        self.verify_frame = ttk.Frame(notebook)

        notebook.add(self.keys_frame, text="1. Keys")
        notebook.add(self.sign_frame, text="2. Sign")
        notebook.add(self.verify_frame, text="3. Verify")

        self._build_keys_tab()
        self._build_sign_tab()
        self._build_verify_tab()

    # ----- Keys tab -----
    def _build_keys_tab(self):
        top = ttk.Frame(self.keys_frame)
        top.pack(fill="x", pady=10)

        bits_label = ttk.Label(top, text="Key size (bits):")
        bits_label.pack(side="left")

        self.bits_var = tk.IntVar(value=512)
        bits_box = ttk.Combobox(
            top, textvariable=self.bits_var,
            values=[512, 768, 1024],
            width=10, state="readonly"
        )
        bits_box.pack(side="left", padx=5)

        gen_btn = ttk.Button(top, text="Generate New Key Pair",
                             command=self.on_generate_keys)
        gen_btn.pack(side="left", padx=10)

        info_label = ttk.Label(
            self.keys_frame,
            text="Public key = (n, e)\nPrivate key = d\nKeep d secret. Public key (n, e) is shared for verification.",
            style="Small.TLabel"
        )
        info_label.pack(anchor="w", pady=(0, 5))

        # public key box
        pub_frame = ttk.LabelFrame(self.keys_frame, text="Public Key (share with others)")
        pub_frame.pack(fill="both", expand=True, pady=5)

        self.pub_text = tk.Text(
            pub_frame, height=6, wrap="word",
            bg="#1e1e1e", fg="#9ef1ff", insertbackground="#ffffff"
        )
        self.pub_text.pack(fill="both", expand=True, padx=5, pady=5)

        # private key box
        priv_frame = ttk.LabelFrame(self.keys_frame, text="Private Key (keep secret)")
        priv_frame.pack(fill="both", expand=True, pady=5)

        self.priv_text = tk.Text(
            priv_frame, height=4, wrap="word",
            bg="#1e1e1e", fg="#ffb3b3", insertbackground="#ffffff"
        )
        self.priv_text.pack(fill="both", expand=True, padx=5, pady=5)

    def on_generate_keys(self):
        bits = int(self.bits_var.get())
        self.pub_text.delete("1.0", "end")
        self.priv_text.delete("1.0", "end")
        self.pub_text.insert("end", f"Generating {bits}-bit RSA key pair...\nPlease wait...")
        self.pub_text.update()

        try:
            n, e, d = generate_keypair(bits)
        except Exception as ex:
            messagebox.showerror("Error", f"Key generation failed: {ex}")
            return

        self.n, self.e, self.d = n, e, d
        self.state = KeyState.HAVE_KEYS

        self.pub_text.delete("1.0", "end")
        self.pub_text.insert("end", f"n (modulus):\n{n}\n\n")
        self.pub_text.insert("end", f"e (public exponent):\n{e}\n")

        self.priv_text.delete("1.0", "end")
        self.priv_text.insert("end", f"d (private exponent):\n{d}\n")

        messagebox.showinfo(
            "Keys generated",
            "RSA key pair generated successfully.\nYou can now sign and verify messages."
        )

        # also pre-fill public key fields in verify tab
        self.verify_n_var.set(str(n))
        self.verify_e_var.set(str(e))

    # ----- Sign tab -----
    def _build_sign_tab(self):
        msg_frame = ttk.LabelFrame(self.sign_frame, text="Message to sign")
        msg_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.sign_message_text = tk.Text(
            msg_frame, height=8, wrap="word",
            bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff"
        )
        self.sign_message_text.pack(fill="both", expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(self.sign_frame)
        btn_frame.pack(fill="x", pady=5)

        sign_btn = ttk.Button(btn_frame, text="Create Digital Signature",
                              command=self.on_sign_message)
        sign_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(
            btn_frame, text="Clear",
            command=lambda: self.sign_message_text.delete("1.0", "end")
        )
        clear_btn.pack(side="left", padx=5)

        sig_frame = ttk.LabelFrame(self.sign_frame, text="Generated Signature (Base64)")
        sig_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.signature_text = tk.Text(
            sig_frame, height=6, wrap="word",
            bg="#1e1e1e", fg="#c3ffab", insertbackground="#ffffff"
        )
        self.signature_text.pack(fill="both", expand=True, padx=5, pady=5)

    def on_sign_message(self):
        if self.state != KeyState.HAVE_KEYS or not self.n or not self.d:
            messagebox.showwarning(
                "No keys",
                "Generate an RSA key pair first on the 'Keys' tab."
            )
            return

        message = self.sign_message_text.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("Empty message", "Please type a message to sign.")
            return

        try:
            signature_b64 = sign_message(message, self.n, self.d)
        except Exception as ex:
            messagebox.showerror("Error", f"Signing failed: {ex}")
            return

        self.signature_text.delete("1.0", "end")
        self.signature_text.insert("end", signature_b64)
        messagebox.showinfo(
            "Signature created",
            "Digital signature generated successfully.\nCopy it and use it on the Verify tab."
        )

    # ----- Verify tab -----
    def _build_verify_tab(self):
        key_frame = ttk.LabelFrame(self.verify_frame, text="Public Key for Verification")
        key_frame.pack(fill="x", padx=5, pady=5)

        n_label = ttk.Label(key_frame, text="n (modulus):")
        n_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.verify_n_var = tk.StringVar()
        n_entry = ttk.Entry(key_frame, textvariable=self.verify_n_var, width=80)
        n_entry.grid(row=0, column=1, sticky="we", padx=5, pady=2)

        e_label = ttk.Label(key_frame, text="e (public exponent):")
        e_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.verify_e_var = tk.StringVar()
        e_entry = ttk.Entry(key_frame, textvariable=self.verify_e_var, width=20)
        e_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        key_frame.columnconfigure(1, weight=1)

        msg_frame = ttk.LabelFrame(self.verify_frame, text="Message")
        msg_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.verify_message_text = tk.Text(
            msg_frame, height=6, wrap="word",
            bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff"
        )
        self.verify_message_text.pack(fill="both", expand=True, padx=5, pady=5)

        sig_frame = ttk.LabelFrame(self.verify_frame, text="Signature (Base64)")
        sig_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.verify_signature_text = tk.Text(
            sig_frame, height=4, wrap="word",
            bg="#1e1e1e", fg="#c3ffab", insertbackground="#ffffff"
        )
        self.verify_signature_text.pack(fill="both", expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(self.verify_frame)
        btn_frame.pack(fill="x", pady=5)

        verify_btn = ttk.Button(
            btn_frame, text="Verify Signature",
            command=self.on_verify_signature
        )
        verify_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(
            btn_frame, text="Clear",
            command=self._clear_verify_fields
        )
        clear_btn.pack(side="left", padx=5)

        self.verify_result_label = ttk.Label(
            self.verify_frame, text="",
            font=("Segoe UI", 14, "bold")
        )
        self.verify_result_label.pack(pady=10)

    def _clear_verify_fields(self):
        self.verify_message_text.delete("1.0", "end")
        self.verify_signature_text.delete("1.0", "end")
        self.verify_result_label.config(text="")

    def on_verify_signature(self):
        n_str = self.verify_n_var.get().strip()
        e_str = self.verify_e_var.get().strip()
        if not n_str or not e_str:
            messagebox.showwarning("Missing key", "Please paste a public key (n and e).")
            return
        try:
            n = int(n_str)
            e = int(e_str)
        except ValueError:
            messagebox.showerror("Invalid key", "Public key values must be integers.")
            return

        message = self.verify_message_text.get("1.0", "end").strip()
        signature_b64 = self.verify_signature_text.get("1.0", "end").strip()
        if not message or not signature_b64:
            messagebox.showwarning("Missing data", "Please provide both message and signature.")
            return

        ok = verify_signature(message, signature_b64, n, e)
        if ok:
            self.verify_result_label.config(
                text="✅ Signature is VALID",
                foreground="#00ff88"
            )
            # success
        else:
            self.verify_result_label.config(
                text="❌ Signature is INVALID",
                foreground="#ff5555"
            )

def main():
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
