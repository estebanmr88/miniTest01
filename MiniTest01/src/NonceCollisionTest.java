
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

public class NonceCollisionTest {

    public static void main(String[] args) {
        int numberOfNoncesToGenerate = 100000;
        SecureRandom secureRandom = new SecureRandom();
        Set<Long> generatedNonces = new HashSet<>();
        boolean isCollisionDetected = false;

        System.out.println("Generating " + numberOfNoncesToGenerate + " random 96-bit nonces.");

        for (int i = 0; i < numberOfNoncesToGenerate; i++) {
            //96-bit nonce
            byte[] nonceBytes = new byte[12];
            //The nonce is filled with random bytes.
            secureRandom.nextBytes(nonceBytes);

            long nonceAsLongType = 0;
            // I convert my byte array to a loing for simpliers comparison. I used the first 8 bytes for the long representation.
            for (int j = 0; j < 8; j++) {
                nonceAsLongType = (nonceAsLongType << 8) | (nonceBytes[j] & 0xFF);
            }
            //If the genereated nonce is repeated, I stop the loop and alert a message of collision.
            if (generatedNonces.contains(nonceAsLongType)) {
                isCollisionDetected = true;
                System.out.println("Collision detected! Nonce: " + nonceAsLongType + " (at iteration " + (i + 1) + ")");
                break;
            }

            generatedNonces.add(nonceAsLongType);
            //I print the number of generated nonce, evert 10000. This message is only for informational purposes.
            if ((i + 1) % 10000 == 0) {
                System.out.println("Generated " + (i + 1) + " nonces.");
            }
        }
        if (!isCollisionDetected) {
            System.out.println("No collisions detected after " + numberOfNoncesToGenerate + " nonces generated.");
        }
    }
}
