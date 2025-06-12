🔗 Blockchain Implementation in Java

This project is a simple blockchain prototype built using Java. It helps you understand how blockchain works by demonstrating the core concepts like:

✅ Block creation

🔒 Hashing using SHA-256

⛏️ Proof-of-Work (mining)

🔗 Linking blocks to form a chain

🔍 Chain validation

 What’s Inside?

Each block contains:

Data (like a message or transaction)

Timestamp

Hash of the current block

Hash of the previous block

Nonce (used for mining)


Features:

Basic structure of a blockchain

Simple mining process using Proof-of-Work

Validation to check blockchain integrity

Why Java?

Java is widely used, secure, and object-oriented — making it perfect for understanding how blockchain technology works at the code level.

# Blockchain-implementation-using-Java-import java.util.ArrayList;
import java.util.Date;
import java.security.MessageDigest;

class Block {
    public String hash;
    public String previousHash;
    private String data; // your data goes here (e.g., transactions)
    private long timeStamp;
    private int nonce;

    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        String input = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
        return applySha256(input);
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0'); // create a string with difficulty * "0"
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined!!! : " + hash);
    }

    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

public class Blockchain {
    public static ArrayList<Block> blockchain = new ArrayList<>();
    public static int difficulty = 4;

    public static void main(String[] args) {
        System.out.println("Trying to Mine block 1...");
        blockchain.add(new Block("First block data", "0"));
        blockchain.get(0).mineBlock(difficulty);

        System.out.println("Trying to Mine block 2...");
        blockchain.add(new Block("Second block data", blockchain.get(blockchain.size() - 1).hash));
        blockchain.get(1).mineBlock(difficulty);

        System.out.println("Trying to Mine block 3...");
        blockchain.add(new Block("Third block data", blockchain.get(blockchain.size() - 1).hash));
        blockchain.get(2).mineBlock(difficulty);

        System.out.println("\nBlockchain is Valid: " + isChainValid());

        System.out.println("\nBlockchain contents:");
        for (Block block : blockchain) {
            System.out.println("Hash: " + block.hash);
            System.out.println("Previous Hash: " + block.previousHash);
            System.out.println("-------------------------");
        }
    }

    public static Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;

        for (int i = 1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i - 1);

            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                System.out.println("Current Hashes not equal");
                return false;
            }

            if (!currentBlock.previousHash.equals(previousBlock.hash)) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
        }

        return true;
    }
}
