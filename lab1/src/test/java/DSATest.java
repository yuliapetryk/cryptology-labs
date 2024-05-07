import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;


public class DSATest {

    private DSA dsa;
    private BigInteger message;
    private BigInteger[] signature;

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException {
        dsa = new DSA();
        message = new BigInteger("44211989442290002");
        signature = dsa.sign(message);
    }

    @Test
    public void testDSATrue()  {
        System.out.println("Signature: " + signature[0] + ", " + signature[1]);
        assertTrue(dsa.verify(message, signature), "Signature verification failed for the same message");
    }

    @Test
    public void testDSAFalse() {
        BigInteger message2 = new BigInteger("234666788840273118");
        assertFalse(dsa.verify(message2, signature), "Signature verification did not fail for a different message");
    }
}
