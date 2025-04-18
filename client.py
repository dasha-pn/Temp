"""Client"""

import socket
import threading
from sympy import randprime

def gcd(a, b):
    """
    Compute the greatest common divisor (GCD) of two integers using the Euclidean algorithm.

    Parameters:
        a (int): First integer.
        b (int): Second integer.

    Returns:
        int: The GCD of a and b.
    """

    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e modulo phi using the extended Euclidean algorithm.

    Parameters:
        e (int): The exponent.
        phi (int): Euler's totient function φ(n).

    Returns:
        int: The modular inverse of e modulo phi.
    """

    def extended_gcd(a, b):
        if b == 0:
            return (1, 0)
        else:
            x1, y1 = extended_gcd(b, a % b)
            x, y = y1, x1 - (a // b) * y1
            return (x, y)

    x, y = extended_gcd(e, phi)
    return x % phi

class Client:
    """
    A client that connects to the server, performs RSA key exchange,
    and sends/receives encrypted messages in a chat system.
    """

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """
        Initialize the client with server connection details and username.

        Parameters:
            server_ip (str): The IP address of the server.
            port (int): The port number of the server.
            username (str): The username to identify the client.
        """

        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        """
        Establish a connection to the server, perform RSA key exchange,
        and start the read and write threads for message handling.
        """

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server:", e)
            return

        self.s.send(self.username.encode())

        other_key_data = self.s.recv(1024).decode()
        e_other, n_other = map(int, other_key_data.split(","))
        self.other_public_key = (e_other, n_other)

        p = randprime(100, 1000)
        q = randprime(100, 1000)
        while p == q:
            q = randprime(100, 1000)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 3
        while e < phi:
            if gcd(e, phi) == 1:
                break
            e += 2
        d = mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

        self.s.send(f"{e},{n}".encode())

        print(f"Connected to server as {self.username}")

        threading.Thread(target=self.read_handler).start()
        threading.Thread(target=self.write_handler).start()

    def read_handler(self):
        """
        Thread handler for receiving encrypted messages from the server,
        decrypting them using the private key, and printing the plaintext.
        """

        while True:
            try:
                data = self.s.recv(1024).decode()
                if not data:
                    break

                parts = data.split()
                decrypted_chars = []
                d, n = self.private_key

                for part in parts:
                    c = int(part)
                    m = pow(c, d, n)
                    decrypted_chars.append(chr(m))

                message = ''.join(decrypted_chars)
                print(f"\n{message}")
            except Exception as e:
                print("[client]: error while decrypting message:", e)
                break

    def write_handler(self):
        """
        Thread handler for reading user input, encrypting each character with
        the server's public key, and sending the encrypted message.
        """

        while True:
            message = input()
            if not message:
                continue

            encrypted = []
            e, n = self.other_public_key

            for char in message:
                m = ord(char)
                c = pow(m, e, n)
                encrypted.append(str(c))

            encrypted_message = ' '.join(encrypted)
            self.s.send(encrypted_message.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "user1")
    cl.init_connection()
