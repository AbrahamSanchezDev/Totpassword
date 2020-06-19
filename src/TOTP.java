import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URL;
import java.util.TimeZone;

/**
 * This is an example implementation of the OATH TOTP algorithm. Visit
 * www.openauthentication.org for more information.
 *
 * @author Johan Rydell, PortWise, Inc.
 */

public class TOTP {

    private TOTP() {
    }

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a
     * Hashed Message Authentication Code with the crypto hash algorithm as a
     * parameter.
     *
     * @param crypto   crypto: the crypto algorithm (HmacSHA1, HmacSHA256,
     *                 HmacSHA512)
     * @param keyBytes keyBytes: the bytes to use for the HMAC key
     * @param text     text: the message or text to be authenticated. authenticated
     */

    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex hex: the HEX string
     *
     * @return A @return: a byte array
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // values Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final long[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8
            = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000L };

    /**
     * This method generates an a TOTP value for the given set of parameters.
     *
     * @param key          key: the shared secret, HEX encoded
     * @param time         time: a value that reflects a time
     * @param returnDigits returnDigits: number of digits to return
     *
     * @return A @return: a numeric String in base 10 that includes
     *         {@link truncationDigits} digits
     */

    public static String generateTOTP(String key, String time, String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    /**
     * This method generates an a TOTP value for the given set of parameters.
     *
     * @param key          key: the shared secret, HEX encoded
     * @param time         time: a value that reflects a time
     * @param returnDigits returnDigits: number of digits to return
     *
     * @return A @return: a numeric String in base 10 that includes
     *         {@link truncationDigits} digits
     */

    public static String generateTOTP256(String key, String time, String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    /**
     * This method generates an a TOTP value for the given set of parameters.
     *
     * @param key          key: the shared secret, HEX encoded
     * @param time         time: a value that reflects a time
     * @param returnDigits returnDigits: number of digits to return
     *
     * @return A @return: a numeric String in base 10 that includes
     *         {@link truncationDigits} digits
     */

    public static String generateTOTP512(String key, String time, String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    /**
     * This method generates an a TOTP value for the given set of parameters.
     *
     * @param key          key: the shared secret, HEX encoded
     * @param time         time: a value that reflects a time
     * @param returnDigits returnDigits: number of digits to return
     * @param crypto       crypto: the crypto function to use
     *
     * @return A @return: a numeric String in base 10 that includes
     *         {@link truncationDigits} digits
     */

    public static String generateTOTP(String key, String time, String returnDigits, String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Complaint Compliant with base RFC 4226 (HOTP)

        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        long binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        long todal = (DIGITS_POWER[codeDigits]);

        long lotp = binary % todal;
        result = Long.toString(lotp);
        // int otp = binary % todal;
        // result = Integer.toString(otp);

        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    public static void old() {
        // Seed for HMAC-SHA512 - 64 bytes
        String seed64 = "6162726168616d5f67746f40686f746d61696c2e636f6d48454e4e47454348414c4c454e4745303033"
                + "6162726168616d5f67746f40686f746d61696c2e636f6d48454e4e47454348414c4c454e4745303033";
        long T0 = 0;
        long X = 30;
        long today = Math.round(new Date().getTime() / 1000);
        long testTime[] = { today };

        String steps = "0";
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        try {
            System.out.println("+---------------+-----------------------+" + "------------------+--------+--------+");
            System.out.println("|  Time(sec)    |   Time (UTC format)   " + "| Value of T(Hex)  |  TOTP  | Mode   |");
            System.out.println("+---------------+-----------------------+" + "------------------+--------+--------+");
            for (int i = 0; i < testTime.length; i++) {
                long T = (testTime[i] - T0) / X;
                steps = Long.toHexString(T).toUpperCase();

                while (steps.length() < 16)
                    steps = "0" + steps;
                String fmtTime = String.format("%1$-11s", testTime[i]);
                String utcTime = df.format(new Date(testTime[i] * 1000));

                System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
                System.out.println(generateTOTP(seed64, steps, "10", "HmacSHA512") + "| SHA512 |");

                System.out
                        .println("+---------------+-----------------------+" + "------------------+--------+--------+");
            }
        } catch (final Exception e) {
            System.out.println("Error : " + e);
        }
    }

    // Char -> Decimal -> Hex
    public static String convertStringToHex(String str) {

        StringBuffer hex = new StringBuffer();

        // loop chars one by one
        for (char temp : str.toCharArray()) {

            // convert char to int, for char `a` decimal 97
            int decimal = (int) temp;

            // convert int to hex, for decimal 97 hex 61
            hex.append(Integer.toHexString(decimal));
        }

        return hex.toString();

    }

    // Hex -> Decimal -> Char
    public static String convertHexToString(String hex) {

        StringBuilder result = new StringBuilder();

        // split into two chars per loop, hex, 0A, 0B, 0C...
        for (int i = 0; i < hex.length() - 1; i += 2) {

            String tempInHex = hex.substring(i, (i + 2));

            // convert hex to decimal
            int decimal = Integer.parseInt(tempInHex, 16);

            // convert the decimal to char
            result.append((char) decimal);

        }

        return result.toString();

    }

    public static void main(String[] args) {
        old();
        System.out.println("Start Testing");
        Date date = new Date();
        System.out.println("Date : " + date);
        System.out.println("Date Time : " + date.getTime());
        String email = "abraham_gto@hotmail.com:";
        String key = "abraham_gto@hotmail.comHENNGECHALLENGE003";
        System.out.println(convertStringToHex(key));
        key = convertStringToHex(key);
        String part = key.substring(0, 8);
        key = key + key + key + part;

        System.out.println(convertHexToString(key));
        // key = key + key + key + key;
        // key = key.substring(0, 64);

        String curKeyFirst = key.substring(0, 8);
        String seed64 = key + key + key + curKeyFirst;
        // key = seed64;
        // date = new Date(2005, 03, 18, 01, 58, 29);
        // date.setTime(10);
        long T0 = 0;
        long X = 30;
        long C = Math.round((date.getTime() / 1000));
        System.out.println("Time In Secons is: ");
        System.out.println(C);
        long T = (C - T0) / X;
        // System.out.println("Now T is ");
        // System.out.println(T);
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String utcTime = df.format(new Date(C * 1000));
        System.out.println(utcTime);

        String steps = Long.toHexString(T).toUpperCase();
        String code = generateTOTP512(seed64, steps, "10");
        System.out.println("code Is");
        System.out.println(code);

        String encoded = Base64.getEncoder().encodeToString((email + code).getBytes());
        System.out.println(encoded);

        // String url = "https://api.challenge.hennge.com/challenges/003";
        // URL obj = new URL(url);
    }
}