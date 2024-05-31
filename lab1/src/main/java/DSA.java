import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

public class DSA {

    private BigInteger p, q, g, privateKey, publicKey;
    private int keySize = 1024;

    public DSA() throws NoSuchAlgorithmException, InvalidKeySpecException {
        generateParameters();
    }

    private void generateParameters() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(keySize, random);

        KeyPair keyPair = keyGen.generateKeyPair();

        privateKey = ((DSAPrivateKey) keyPair.getPrivate()).getX();
        publicKey = ((DSAPublicKey) keyPair.getPublic()).getY();

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), DSAPrivateKeySpec.class);

        p = privateKeySpec.getP();
        q = privateKeySpec.getQ();
        g = privateKeySpec.getG();
    }

    public BigInteger[] sign(BigInteger message) {
        BigInteger k;
        do {
            k = new BigInteger(q.bitLength(), new SecureRandom()).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } while (k.gcd(q).compareTo(BigInteger.ONE) != 0);

        BigInteger r = g.modPow(k, p).mod(q);
        BigInteger s = k.modInverse(q).multiply(message.add(privateKey.multiply(r))).mod(q);

        return new BigInteger[]{r, s};
    }

    public boolean verify(BigInteger message, BigInteger[] signature) {
        BigInteger r = signature[0];
        BigInteger s = signature[1];

        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(q) >= 0 || s.compareTo(BigInteger.ONE) < 0 || s.compareTo(q) >= 0) {
            return false;
        }

        BigInteger w = s.modInverse(q);
        BigInteger u1 = message.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);
        BigInteger v = g.modPow(u1, p).multiply(publicKey.modPow(u2, p)).mod(p).mod(q);

        return v.equals(r);
    }
}