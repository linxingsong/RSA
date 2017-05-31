//XingSong Lin
//RSA
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
 
public class RSA
{
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int        bitlength = 16;
    private Random     r;
 
    public RSA()
    {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);  //N = p *q
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // phi = (p-1)(q-1)
        e = BigInteger.probablePrime(bitlength / 2, r);  //public key
        System.out.println("e: "+e);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
        {
            e.add(BigInteger.ONE);  
        }
        d = e.modInverse(phi);  //private key    d = (publicKey^-1) * mod(phi)
    }
 
    public RSA(BigInteger e, BigInteger d, BigInteger N)
    {
        this.e = e;
        this.d = d;
        this.N = N;
    }
 
    public static void main(String[] args) throws IOException
    {
        RSA rsa = new RSA();
        String teststring;
        
        System.out.println( "p: " + rsa.p );
		System.out.println( "q: " + rsa.q );
		System.out.println( "n = p*q: " + rsa.N );
		System.out.println( "phi = (p - 1)*(q - 1): " + rsa.phi );
		System.out.println( "The publicKey: " + rsa.e );
		System.out.println( "The privateKey: " + rsa.d );
		
        System.out.println("Person A: Enter the plain text:");
        Scanner s = new Scanner(System.in);
        teststring = s.nextLine();
        System.out.println("Person A: Encrypting String: " + teststring);
        System.out.println("Person A: String in Bytes: "
                + bytesToString(teststring.getBytes()));
        // encrypt
        byte[] encrypted = rsa.encrypt(teststring.getBytes());
        System.out.println("Person A: Encrypting Bytes send to person B: " + bytesToString(encrypted));
        // decrypt
        byte[] decrypted = rsa.decrypt(encrypted);
        
        System.out.println("Person B: Decrypting Bytes recesive from person A: " + bytesToString(decrypted));
        System.out.println("Person B: Decrypted String from bytes: " + new String(decrypted));
    }
 
    private static String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
 
    // Encrypt message
    public byte[] encrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(e, N).toByteArray(); // C = (message^publicKey) * mod N
    }
 
    // Decrypt message
    public byte[] decrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray(); // C = (encrypted^privateKey) * mod N
    }
}