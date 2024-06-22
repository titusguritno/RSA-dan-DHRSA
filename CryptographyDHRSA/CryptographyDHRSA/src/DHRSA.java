
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

public class DHRSA {

    private BigInteger n;
    private BigInteger d;
    private BigInteger e;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Diffie-Hellman parameters
    private BigInteger p;
    private BigInteger g;
    private BigInteger privateDHValue;
    private BigInteger publicDHValue;
    private BigInteger sharedKey; // Shared secret key

    public static class PublicKey {

        private final String e;
        private final String n;

        public PublicKey(String e, String n) {
            this.e = e;
            this.n = n;
        }

        public String getE() {
            return e;
        }

        public String getN() {
            return n;
        }
    }

    public static class PrivateKey {

        private final String d;
        private final String n;

        public PrivateKey(String n, String d) {
            this.n = n;
            this.d = d;
        }

        public String getD() {
            return d;
        }

        public String getN() {
            return n;
        }
    }

    public DHRSA() {
        generateRSAKeyPair(3072);
//        generateDHParameters(3072);
    }

    public DHRSA(int bits) {
        generateRSAKeyPair(bits);
        generateDHParameters(bits);
    }

    public final void generateRSAKeyPair(int bits) {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bits / 2, 100, random);
        BigInteger q = new BigInteger(bits / 2, 100, random);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        n = p.multiply(q);
        e = new BigInteger("3");

        while (phi.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }

        d = e.modInverse(phi);
        publicKey = new PublicKey(e.toString(), n.toString());
        privateKey = new PrivateKey(d.toString(), n.toString());
    }

    public final void generateDHParameters(int bits) {
        SecureRandom random = new SecureRandom();
        this.p = new BigInteger(bits, 100, random);
        this.g = new BigInteger(bits - 1, random);
        privateDHValue = new BigInteger(bits - 1, random);
        publicDHValue = g.modPow(privateDHValue, p);
    }

    public BigInteger getPublicDHValue() {
        return publicDHValue;
    }

    public BigInteger computeSharedKey(BigInteger otherPublicKeyDH) {
        // Calculate shared key using Diffie-Hellman private value
        sharedKey = otherPublicKeyDH.modPow(privateDHValue, p);
//        sharedKey = otherPublicKeyDH.modPow(d, n);
        return sharedKey;
    }

    public String encryptRSA(String plainData, PublicKey publicKey) {
        byte[] plainBytes = plainData.getBytes();
        byte[] encryptedBytes = (new BigInteger(plainBytes)).modPow(new BigInteger(publicKey.getE()), new BigInteger(publicKey.getN())).toByteArray();
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptRSA(String encryptedData) {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = (new BigInteger(1, encryptedBytes)).modPow(d, n).toByteArray();
        return new String(decryptedBytes);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
