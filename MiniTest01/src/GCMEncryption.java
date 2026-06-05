
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class GCMEncryption {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private final SecretKey sharedKey;
    private final int deviceId;
    private long deterministicCounter = 0;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicLong messageRandomCounter = new AtomicLong(0);

    public GCMEncryption(SecretKey key, int deviceId) {
        this.sharedKey = key;
        this.deviceId = deviceId;
    }

    /*
    createDeterministicNonce()
    Creates a deterministic nonce based on the counter and a device ID.
    IN* NONE
    OUT* BYTE ARRAY.
     */
    public byte[] createDeterministicNonce() throws Exception {
        ByteBuffer nonceBuffer = ByteBuffer.allocate(GCM_IV_LENGTH);
        nonceBuffer.putInt(deviceId);
        nonceBuffer.putLong(deterministicCounter++);
        return nonceBuffer.array();
    }

    /*
    EncryptWithGMC()
    The method encrypts a plaintext using GCM. You can provide 1 to encrypt using deterministc approach or 0 for a random approach. 
    IN* BYTE ARRAY plaintext, BOOLEAN isRandomOrDeterministic
    OUT* BYTE ARRAY.
     */
    public byte[] encryptWithGMC(byte[] plaintext, boolean isRandomOrDeterministicApproach) throws Exception {
        //CGM Chain mode with AES.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = isRandomOrDeterministicApproach ? createDeterministicNonce() : createRandomNonce();
        GCMParameterSpec gcmSpecifications = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        //Cipher initilization
        cipher.init(Cipher.ENCRYPT_MODE, sharedKey, gcmSpecifications);
        //doFinal encrytps or decrypts based on cipher.init().
        byte[] ciphertext = cipher.doFinal(plaintext);
        //I create the buffer size with the nonce's length and the ciphertext's length. 
        ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
        byteBuffer.put(nonce);
        byteBuffer.put(ciphertext);
        return byteBuffer.array();
    }

    /*
    decryptWithGCM()
    GCM Decryption of a block cipher. 
    IN* BYTE ARRAY blockCipher
    OUT* BYTE ARRAY.
     */
    public byte[] decryptWithGCM(byte[] blockCipher) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(blockCipher);
        byte[] nonce = new byte[GCM_IV_LENGTH];
        //I segregate the nonce and the ciphertext from the block cipher.
        byteBuffer.get(nonce);
        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);
        //CGM Chain mode with AES.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpecifications = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, sharedKey, gcmSpecifications);
        return cipher.doFinal(ciphertext);
    }

    /*
    createRandomNonce()
    Generation of a random nonce approach for GCM. 
    IN* NONE
    OUT* BYTE ARRAY.
     */
    public byte[] createRandomNonce() throws Exception {
        ByteBuffer nonceRandomBuffer = ByteBuffer.allocate(GCM_IV_LENGTH);
        // First 4 bytes: Unique Device ID
        nonceRandomBuffer.putInt(deviceId);
        //Random data in bytes.
        byte[] randomNonceSection = new byte[8];
        secureRandom.nextBytes(randomNonceSection);
        nonceRandomBuffer.put(randomNonceSection);

        // I combine the counter with a random section to avoid the birthday attack for long-lived sessions.
        long counterValue = messageRandomCounter.getAndIncrement();
        ByteBuffer counterBuffer = ByteBuffer.allocate(8);
        counterBuffer.putLong(counterValue);
        byte[] counterBytes = counterBuffer.array();

        // XOR the counter with the random part. This produces the counter's uniqueness.
        for (int i = 0; i < 8; i++) {
            randomNonceSection[i] ^= counterBytes[i];
        }
        // I reset the position after putting the deviceId.
        nonceRandomBuffer.position(4);
        nonceRandomBuffer.put(randomNonceSection);

        return nonceRandomBuffer.array();
    }

    public static void main(String[] args) throws Exception {
        // 256-bits key with AES.
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sharedKey = keyGenerator.generateKey();

        //Secret message.
        String plaintext = "This is my secret message for the test. Let's see what happens.";
        testGCM(plaintext, sharedKey);
    }

    static void testGCM(String plaintext, SecretKey sharedKey) {
        try {
            // Creation of two unique devices.
            GCMEncryption device1 = new GCMEncryption(sharedKey, 000001);
            GCMEncryption device2 = new GCMEncryption(sharedKey, 000002);
            //Encryption and decryption of Deterministic Approach
            System.out.println("Deterministic Nonce Approach.\n");
            //I considered the devices are all able to access the shared key.
            byte[] ciphertextOne = device1.encryptWithGMC(plaintext.getBytes(), true);
            byte[] decryptedCiphertextOne = device2.decryptWithGCM(ciphertextOne);
            System.out.println("Original plaintext: " + plaintext);
            System.out.println("\nDecrypted Device #2: " + new String(decryptedCiphertextOne));

            byte[] ciphertextTwo = device2.encryptWithGMC(plaintext.getBytes(), true);
            byte[] decryptedCiphertextTwo = device1.decryptWithGCM(ciphertextTwo);
            System.out.println("\nOriginal plaintext: " + plaintext);
            System.out.println("\nDecrypted Device #1): " + new String(decryptedCiphertextTwo));

            //Encryption and decryption of Random Approach
            System.out.println("\n\nRandom Nonce Approach.\n");
            //I considered the devices are all able to access the shared key.
            ciphertextOne = device1.encryptWithGMC(plaintext.getBytes(), false);
            decryptedCiphertextOne = device2.decryptWithGCM(ciphertextOne);
            System.out.println("Original: " + plaintext);
            System.out.println("\nDecrypted Device #2): " + new String(decryptedCiphertextOne));

            ciphertextTwo = device2.encryptWithGMC(plaintext.getBytes(), false);
            decryptedCiphertextTwo = device1.decryptWithGCM(ciphertextTwo);
            System.out.println("\nOriginal: " + plaintext);
            System.out.println("\nDecrypted Device #1): " + new String(decryptedCiphertextTwo));

            System.out.println("\nMultiple Messages from a device.");
            for (int i = 0; i < 10000; i++) {
            byte[] ciphertextMulti = device1.encryptWithGMC(("Message " + (i + 1)).getBytes(), false);
            byte[] decryptedMulti = device2.decryptWithGCM(ciphertextMulti);
            System.out.println("\nOriginal: Message " + (i + 1) + ", Decrypted: " + new String(decryptedMulti));
        }

        } catch (Exception ex) {
            ex.getLocalizedMessage();
        }
    }
}
