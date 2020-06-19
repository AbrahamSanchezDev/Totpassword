import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.TimeZone;

/**
 * This is an example implementation of the OATH TOTP algorithm. Visit
 * www.openauthentication.org for more information.
 *
 * @author Johan Rydell, PortWise, Inc.
 * 
 *         Modified by Abraham Sanchez to generate up to 10 digits
 */

public class TOTP {

    private TOTP() {
    }

    // #region Variables
    static String email = "abraham_gto@hotmail.com:";
    static String key = "abraham_gto@hotmail.comHENNGECHALLENGE003";
    static long T0 = 0;
    static long X = 30;
    private static final long[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8 9 10
            = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000L };

    // #endregion
    public static void main(String[] args) {
        GetKey(key, 10);

        // TestOriginals();
    }

    // #region TOTP
    // Returns a key with the given keytext with the length of digits
    public static String GetKey(String keyText, int digits) {
        Date now = new Date();
        long nowInSeconds = now.getTime() / 1000;
        String code = Create(keyText, nowInSeconds, digits);
        System.out.println("Code : " + code);
        return code;
    }

    // #region Originals Test
    static String originalKey = "12345678901234567890";
    static long originalTestTime[] = { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };
    static String originalExpected[] = { "90693936", "25091201", "99943326", "93441116", "38618901", "47863826" };
    // Seed for HMAC-SHA512 - 64 bytes
    static String seed64 = "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930"
            + "3132333435363738393031323334353637383930" + "31323334";

    // Test that the original values are correct
    public static void TestOriginals() {
        int success = 0;
        int fail = 0;
        for (int i = 0; i < originalTestTime.length; i++) {
            String code = Create(originalKey, originalTestTime[i], 8);
            boolean same = originalExpected[i].equals(code);
            if (!same) {
                System.out.println(code + " needs to be : " + originalExpected[i]);
                fail++;
            } else {
                success++;
            }
        }
        System.out.println("Total Pass : " + success + "  Total Failed: " + fail);

    }

    // Test if the original key is the same as in the example
    private static void TestOriginalKey64() {
        String originalInHex = StringToHex(originalKey);
        System.out.println("Original Key : " + originalInHex);
        String finalPart = originalInHex.substring(0, 8);
        String finalKey = originalInHex + originalInHex + originalInHex + finalPart;

        boolean same = finalKey.equals(seed64);
        System.out.println("Same Key = " + same);
        if (!same) {
            System.out.println(finalKey);
            System.out.println(seed64);
        }
    }
    // #endregion

    // #region text to Hex and Hex to text
    // Char -> Decimal -> Hex
    public static String StringToHex(String str) {
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
    public static String HexToString(String hex) {
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
    // #endregion

    // Create a TOTP Code with the length of the digits using the given text ,time
    // in seconds
    public static String Create(String keyText, long timeInSeconds, int digits) {
        String finalKey = TextTo64BytesKey(keyText);
        String steps = "0";
        long T = (timeInSeconds - T0) / X;
        steps = Long.toHexString(T).toUpperCase();
        while (steps.length() < 16) {
            steps = "0" + steps;
        }
        PrintHeader();
        PrintData(timeInSeconds, steps);

        String totp = generateTOTP(finalKey, steps, digits, "HmacSHA512");

        System.out.println(totp + "| SHA512 |");
        return totp;
    }

    // Turn the given key to a 64 format
    public static String TextTo64BytesKey(String text) {
        String currentKeyInHex = StringToHex(text);
        String fist8HexPart = currentKeyInHex.substring(0, 8);
        return currentKeyInHex + currentKeyInHex + currentKeyInHex + fist8HexPart;
    }

    // #region Log to console
    // Print the date of the given time in seconds steps is the value of T(Hex)
    public static void PrintData(long timeInSeconds, String steps) {
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String fmtTime = String.format("%1$-11s", timeInSeconds);
        String utcTime = df.format(new Date(timeInSeconds * 1000));
        System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
    }

    // Prints the header
    public static void PrintHeader() {
        System.out.println("+---------------+-----------------------+" + "------------------+--------+--------+");
        System.out.println("|  Time(sec)    |   Time (UTC format)   " + "| Value of T(Hex)  |  TOTP  | Mode   |");
        System.out.println("+---------------+-----------------------+" + "------------------+--------+--------+");
    }

    // #endregion

    // #region Original Algorithm

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a
     * Hashed Message Authentication Code with the crypto hash algorithm as a
     * parameter.
     *
     * @param crypto:   the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text:     the message or text to be authenticated
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
     * @param hex: the HEX string
     *
     * @return: a byte array
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    /**
     * This method generates a TOTP value for the given set of parameters.
     *
     * @param key:          the shared secret, HEX encoded
     * @param time:         a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto:       the crypto function to use
     *
     * @return: a numeric String in base 10 that includes {@link truncationDigits}
     *          digits
     */

    public static String generateTOTP(String key, String time, int returnDigits, String crypto) {
        int codeDigits = returnDigits;
        String result = null;
        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        // Original
        // int otp = binary % DIGITS_POWER[codeDigits];
        // result = Integer.toString(otp);

        // New
        long otp = binary % DIGITS_POWER[codeDigits];
        result = Long.toString(otp);

        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }
    // #endregion
    // #endregion
}