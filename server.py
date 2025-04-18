'''server'''
import socket
import threading
import hashlib
import random

class Server:
    """
    Server class to handle client connections and message broadcasting.
    It uses RSA encryption for secure communication and SHA-256 for message integrity.
    """
    def __init__(self, port: int) -> None:
        """
        Initialize the server with a given port number.
        Generate RSA keys for encryption and decryption.
        
        Args:
            port (int): Port number for the server to listen on.
        """
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.public_key, self.private_key = self.generate_rsa_keys()

    def start(self):
        """
        Start the server to listen for incoming connections.
        Accept client connections and handle them in separate threads.
        """
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            n, e = self.public_key
            c.send(f"{n},{e}".encode())

            client_key_data = c.recv(1024).decode()
            n_c, e_c = map(int, client_key_data.split(','))
            self.client_keys[c] = (n_c, e_c)

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        """
        Broadcast a message to all connected clients.
        Encrypt the message using RSA and send it to each client.

        Args:
            msg (str): The message to be broadcasted.
        """
        for client in self.clients:

            n, e = self.client_keys[client]
            encrypted_msg = [str(self.rsa_encrypt(ord(ch), (n, e))) for ch in msg]
            hash_val = hashlib.sha256(msg.encode()).hexdigest()
            payload = f"{hash_val}|{' '.join(encrypted_msg)}"

            client.send(payload.encode())

    def handle_client(self, c: socket, addr):
        """
        Handle incoming messages from a client.
        Decrypt the message, verify its integrity, and broadcast it to other clients.

        Args:
            c (socket): The client socket.
            addr: The address of the client.
        """
        while True:
            try:
                data = c.recv(4096).decode()
                if not data:
                    continue

                hash_recv, encrypted_msg = data.split('|')
                encrypted_numbers = list(map(int, encrypted_msg.split()))
                decrypted_msg = ''.join(chr(self.rsa_decrypt(num, self.private_key)) \
for num in encrypted_numbers)

                actual_hash = hashlib.sha256(decrypted_msg.encode()).hexdigest()
                if actual_hash != hash_recv:
                    print("Integrity check failed.")
                    continue

                for client in self.clients:
                    if client != c:
                        n, e = self.client_keys[client]
                        encrypted_fwd = [str(self.rsa_encrypt(ord(ch), (n, e))) \
for ch in decrypted_msg]
                        payload = f"{actual_hash}|{' '.join(encrypted_fwd)}"
                        client.send(payload.encode())

            except Exception as e:
                print(f"Error: {e}")
                c.close()
                self.clients.remove(c)
                break

    def generate_rsa_keys(self):
        """
        Generate RSA keys (public and private).
        Select two distinct prime numbers and compute the public and private keys.
        """
        p, q = self.get_primes()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 3
        while self.gcd(e, phi) != 1:
            e += 2
        d = self.modinv(e, phi)
        return (n, e), (n, d)

    def rsa_encrypt(self, m, key):
        """
        RSA encryption function.
        Encrypt a message using the public key.
        """
        n, e = key
        return pow(m, e, n)

    def rsa_decrypt(self, c, key):
        """
        RSA decryption function.
        Decrypt a ciphertext using the private key.
        """
        n, d = key
        return pow(c, d, n)

    def get_primes(self):
        """
        Get two distinct prime numbers from a predefined list.
        These primes are used for RSA key generation.
        The primes are chosen to be small for demonstration purposes.
        In a real-world application, larger primes should be used.
        """
        primes = [61, 53, 59, 47, 71, 67]
        p = random.choice(primes)
        q = random.choice([x for x in primes if x != p])
        return p, q

    def gcd(self, a, b):
        """
        Compute the greatest common divisor (GCD) of two numbers.
        This is used in the RSA key generation process to ensure that the public exponent
        is coprime with phi(n).
        Args:
            a (int): First number.
            b (int): Second number.
        Returns:
            int: The GCD of a and b.
        """
        while b:
            a, b = b, a % b
        return a

    def modinv(self, a, m):
        """
        Modular inverse of a under modulo m.
        This is used to compute the private exponent d in RSA key generation.
        Args:
            a (int): The number to find the inverse of.
            m (int): The modulus.
        Returns:
            int: The modular inverse of a under modulo m.
        """
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

if __name__ == "__main__":
    s = Server(9001)
    s.start()
