public class RC4 extends Cipher {
    private byte[] S = new byte[256];

    public RC4(String plaintext, String key) throws NonASCIIException {
        super(plaintext, key);

        // Key scheduling algorithm
        keyScheduler();
    }

    public byte[] getS() {
        return this.S;
    }

    public void keyScheduler() {
        for(int i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }

        int j = 0;

        for(int h = 0; h < 256; h++) {
            j = (j + (getS()[h] & 0xFF) + (getKey()[h % getKey().length] & 0xFF)) & 0xFF;
            Util.swap(getS(), h, j);
        }
    }

    protected byte[] encrypt() {
        int a = 0,  b = 0;
        int h = 0;
        byte[] text = getPlaintext();
        byte[] ciphertext = new byte[text.length];
        byte[] S = getS();

        for(int i = 0; i < text.length; i++) {
            a = (a + 1) & 0xFF;
            b = (b + (S[a] & 0xFF)) & 0xFF;
            Util.swap(S, a, b);
            h = (S[(S[a] + S[b]) & 0xFF]) & 0xFF;
            ciphertext[i] = (byte) ((text[i] & 0xFF) ^ h);
        }

        return ciphertext;
    }

    protected byte[] decrypt() {
        return this.encrypt();
    }
}
