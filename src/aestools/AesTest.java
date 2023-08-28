package aestools;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class AesTest {
	
	public static final int AES_BLOCK_SIZE = 16;

	public static void main(String[] args) 
	{
		System.out.println("AES key:");
		Scanner inp = new Scanner(System.in);
        String strAesKey = inp.next();
        
        byte[] byAesKey = hexStrToByteArray(strAesKey);
        if (byAesKey == null || byAesKey.length != 16)
        {
        	System.out.println("aes key format invalid");
        	return;
        }
        
        System.out.println("Raw message:");
        String strEncryptMessage = inp.next();
        byte[] byEncryptMsg = hexStrToByteArray(strEncryptMessage);
        if (byEncryptMsg == null || byEncryptMsg.length < 14)
        {
        	System.out.println("aes data invalid");
        	return;
        }
        
        //sequence and raw data lenght
        int jsonMsgLength = ((byEncryptMsg[12] & 0xFF) << 8) + (byEncryptMsg[13] & 0xFF);
        int iv2EncryptDataLen = byEncryptMsg.length - 14;

        //copy iv and encrypt data
        int nIv2DataWithPaddingLen = getEncodeDataLen(jsonMsgLength);
        if (iv2EncryptDataLen != nIv2DataWithPaddingLen)
        {
        	System.out.println("AES data invalid");
        	return;
        }
        byte[] byIv2data = new byte[nIv2DataWithPaddingLen];
        System.arraycopy(byEncryptMsg, 14, byIv2data, 0, nIv2DataWithPaddingLen);
        
        //decrypt data
        SecretUdpUtil test = new SecretUdpUtil(byAesKey);
        byte[] byDecryptData = test.decrypt_iv2data(byIv2data);
        
        //remove padding
        try
        {
			String strDecrypt = new String(byDecryptData, "UTF-8").trim();
			System.out.println("Decrypt message:");
	        System.out.println(strDecrypt);
        }
        catch(Exception except)
        {
        	except.printStackTrace();
        }
	}
	
	static int getEncodeDataLen(int rawMsgLen)
	{
		int remainDataLen = rawMsgLen % AES_BLOCK_SIZE;
		int encodeDataLen = rawMsgLen;
		if (remainDataLen != 0)
		{
			encodeDataLen += (AES_BLOCK_SIZE - remainDataLen);
		}
		
		return encodeDataLen + AES_BLOCK_SIZE; //ad iv
	}
	
    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null) {
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

	
	public static byte[] hexStrToByteArray(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		hexString = hexString.toUpperCase();
		char[] hexCharacter = hexString.toCharArray();
		for (int i = 0; i < hexCharacter.length; i++) {
			if (-1 == charToByte(hexCharacter[i])) {
				return null;
			}
		}

		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));

		}
		return d;
	}

	public static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
}
