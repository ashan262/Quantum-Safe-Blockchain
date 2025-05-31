import json
import time
from hashlib import sha256

# Import PQC signature schemes from pqcrypto library
from pqcrypto.sign import dilithium2, sphincs_haraka128s_simple


# Utility function to compute SHA-256 hash
def compute_hash(data: str) -> str:
    return sha256(data.encode('utf-8')).hexdigest()


# Transaction class: each transaction is signed using Dilithium
class Transaction:
    def __init__(self, sender_public_key: bytes, receiver: str, amount: float, signature: bytes = None):
        self.sender_public_key = sender_public_key
        self.receiver = receiver
        self.amount = amount
        self.signature = signature

    def to_dict(self) -> dict:
        return {
            'sender_public_key': self.sender_public_key.hex(),
            'receiver': self.receiver,
            'amount': self.amount
        }

    def sign_transaction(self, sender_private_key: bytes):
        """
        Sign the transaction data using Dilithium private key.
        """
        message = json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')
        signed = dilithium2.sign(message, sender_private_key)
        self.signature = signed

    def verify_signature(self) -> bool:
        """
        Verify the transaction signature using Dilithium public key.
        """
        message = json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')
        try:
            dilithium2.verify(message, self.signature, self.sender_public_key)
            return True
        except Exception:
            return False


# Block class: each block is signed using SPHINCS+
class Block:
    def __init__(self, index: int, previous_hash: str, transactions: list, timestamp: float = None, signature: bytes = None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.transactions = transactions  # List of Transaction objects
        self.nonce = 0  # Not using PoW; nonce for potential future use
        self.signature = signature

    def to_dict(self) -> dict:
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce
        }

    def compute_block_hash(self) -> str:
        """
        Compute SHA-256 hash of the block's data (excluding signature).
        """
        block_string = json.dumps(self.to_dict(), sort_keys=True)
        return compute_hash(block_string)

    def sign_block(self, sphincs_private_key: bytes):
        """
        Sign the block hash using SPHINCS+ private key.
        """
        block_hash = self.compute_block_hash().encode('utf-8')
        signed = sphincs_haraka128s_simple.sign(block_hash, sphincs_private_key)
        self.signature = signed

    def verify_signature(self, sphincs_public_key: bytes) -> bool:
        """
        Verify the block signature using SPHINCS+ public key.
        """
        block_hash = self.compute_block_hash().encode('utf-8')
        try:
            sphincs_haraka128s_simple.verify(block_hash, self.signature, sphincs_public_key)
            return True
        except Exception:
            return False


# Blockchain class: maintains the chain of blocks
class QuantumSafeBlockchain:
    def __init__(self, authority_public_key: bytes, authority_private_key: bytes):
        self.chain = []
        self.pending_transactions = []
        self.authority_public_key = authority_public_key
        self.authority_private_key = authority_private_key
        # Create the genesis block
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(index=0, previous_hash="0", transactions=[], timestamp=time.time())
        genesis_block.sign_block(self.authority_private_key)
        self.chain.append(genesis_block)

    def get_last_block(self) -> Block:
        return self.chain[-1]

    def add_transaction(self, transaction: Transaction):
        """
        Add a new transaction to the pool of pending transactions.
        Only valid transactions with correct signatures are added.
        """
        if transaction.verify_signature():
            self.pending_transactions.append(transaction)
            return True
        return False

    def create_block(self):
        """
        Create a new block from pending transactions and sign it with SPHINCS+.
        """
        last_block = self.get_last_block()
        new_block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.compute_block_hash(),
            transactions=self.pending_transactions[:]
        )
        new_block.sign_block(self.authority_private_key)
        # Clear pending transactions
        self.pending_transactions = []
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self) -> bool:
        """
        Verify the entire blockchain: block signatures and transaction signatures.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Verify block integrity
            if previous.compute_block_hash() != current.previous_hash:
                return False
            if not current.verify_signature(self.authority_public_key):
                return False

            # Verify transactions inside the block
            for tx_dict, tx in zip(current.to_dict()['transactions'], current.transactions):
                if not tx.verify_signature():
                    return False
        return True


# Utility function to generate PQC key pairs
def generate_dilithium_keys():
    """
    Generate Dilithium2 public and private keys.
    """
    public_key, private_key = dilithium2.generate_keypair()
    return public_key, private_key


def generate_sphincs_keys():
    """
    Generate SPHINCS+ Haraka128s public and private keys.
    """
    public_key, private_key = sphincs_haraka128s_simple.generate_keypair()
    return public_key, private_key


# ------------- Example Usage -------------
if __name__ == "__main__":
    # Generate authority (block signer) keys using SPHINCS+
    sphincs_public, sphincs_private = generate_sphincs_keys()

    # Initialize blockchain with authority keys
    blockchain = QuantumSafeBlockchain(authority_public_key=sphincs_public, authority_private_key=sphincs_private)

    # Generate user keys using Dilithium2
    dilithium_public, dilithium_private = generate_dilithium_keys()

    # Create and sign a new transaction
    tx1 = Transaction(sender_public_key=dilithium_public, receiver="user_ABC", amount=50.0)
    tx1.sign_transaction(sender_private_key=dilithium_private)
    blockchain.add_transaction(tx1)

    # Create another transaction
    tx2 = Transaction(sender_public_key=dilithium_public, receiver="user_XYZ", amount=20.0)
    tx2.sign_transaction(sender_private_key=dilithium_private)
    blockchain.add_transaction(tx2)

    # Mine (create) a new block
    new_block = blockchain.create_block()
    print("New block created:", new_block.to_dict())

    # Verify blockchain integrity
    print("Is blockchain valid?", blockchain.is_chain_valid())
