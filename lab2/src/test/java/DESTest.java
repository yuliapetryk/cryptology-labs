import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class DESTest {
    private List<Integer> IV;
    private String text;
    private String KEY;

    private DES des;

    @Before
    public void setUp() {
        des = new DES();
        IV = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            IV.add(0);
        }
        for (int i = 0; i < 20; i++) {
            IV.add(1);
        }
        for (int i = 0; i < 4; i++) {
            IV.add(0);
        }

        KEY = "1f4f8b113b4a5d66";
    }

    @Test
    public void test1() {

        text = "This is my secret";

        List<Integer> desText = DES.encrypt(IV, text, KEY);

        String ensText = DES.decrypt(IV, desText, KEY);

        assertNotNull("Cipher text should not be null", desText);
        assertEquals("Decrypted text should match the original text", text, ensText);

        System.out.println("Encrypted text: " + des.utils.listToString(desText));
        System.out.println("Decrypted text : " + ensText);
    }


    @Test
    public void test2() {

        text = "This is my secret 1234";

        List<Integer> enсText = DES.encrypt(IV, text, KEY);

        String decText = DES.decrypt(IV, enсText, KEY);

        assertNotNull("Cipher text should not be null", enсText);
        assertEquals("Decrypted text should match the original text", text, decText);

        System.out.println("Encrypted text: " + des.utils.listToString(enсText));
        System.out.println("Decrypted text : " + decText);
    }

}
