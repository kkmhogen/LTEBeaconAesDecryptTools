package aestools;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SecretUdpUtil {
    
    private static final String INSTANCE = "AES/CBC/NoPadding";
    private static final String AES = "AES";
    
    SecretKeySpec mKeySpec;
    IvParameterSpec mIV;
	Cipher mCipher;
    
    public SecretUdpUtil(byte[] key)
    {
    	try
    	{
    		mCipher = Cipher.getInstance(INSTANCE);
    		if (key != null)
    		{
    			mKeySpec = new SecretKeySpec(key, AES);
	    	}
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
    }
   
    public static void test_utils( ) 
    {
    	try
    	{
    		byte[] BYTES_KEY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,0x0, 0x0, 0x0, 0x0,0x0, 0x0, 0x0, 0x1};

    		byte[] iv_key = {
    				(byte)0x94,(byte)0x00,(byte)0xbe,(byte)0x2e,(byte)0xd5,(byte)0x7b,(byte)0xbd,(byte)0x55
    				,(byte)0xee,(byte)0xdc,(byte)0x02,(byte)0xe4,(byte)0x7f,(byte)0x7b,(byte)0x5f,(byte)0x1a};
    		
    		
    		String strDataBefore = "{\"msg\":\"alive\",\"imei\":\"351358812796579\",\"batt\":3512,\"acc\":{\"x\":712,\"y\":-296,\"z\":616},\"temp\":19.0,\"log\":1141157,\"lat\":221738}";

    		SecretUdpUtil util2 = new SecretUdpUtil(BYTES_KEY);
    		util2.set_iv(iv_key);
    		byte encdata3[] = util2.encrypt(strDataBefore.getBytes()); 
    		
    		SecretUdpUtil util3 = new SecretUdpUtil(BYTES_KEY);
    		util3.set_iv(iv_key);
    		byte[]decode = util3.decrypt_data(encdata3);
	        String plainData = new String(decode);
	        System.out.println("plain test:" + plainData);
    	}
    	catch(Exception except)
    	{
    		except.printStackTrace();
    	}
    }
   
	
	public void updateKey(byte[] key)
	{
		try
    	{
	    	mKeySpec = new SecretKeySpec(key, AES);
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
	}
    
    //decrypt
    public byte[] decrypt_data(byte[] enc_data)
    {
        // Ω‚√‹
        byte []decode = null;
        try
        {
	        mCipher.init(Cipher.DECRYPT_MODE, mKeySpec, mIV); 
	        decode = mCipher.doFinal(enc_data);
        }
        catch(Exception except)
        {
        	except.printStackTrace();
        }
        
        return decode;
    }
   
    
    public void set_iv(byte iv[])
    {
    	mIV = new IvParameterSpec(iv);
    }
    
    //Dencrypt data
    public byte[] decrypt_iv2data(byte[] enc_data)
    {
        byte[] iv = new byte[16];
        int copy_data_len = enc_data.length - 16;
        byte[] data = new byte[copy_data_len];

        System.arraycopy(enc_data, 0, iv, 0, 16);
        System.arraycopy(enc_data, 16, data, 0, copy_data_len);
        
        byte []decode = null;
        try
        {
	        mIV = new IvParameterSpec(iv);
	        mCipher.init(Cipher.DECRYPT_MODE, mKeySpec, mIV); 
	        decode = mCipher.doFinal(data);
        }
        catch(Exception except)
        {
        	except.printStackTrace();
        }
        
        return decode;
    }

    public byte[] encrypt(byte data[])  {
        byte[] encode = null;
        try
        {            
            int encodeDataLen = data.length;
            int remainDataLen = encodeDataLen % 16;
            if (remainDataLen != 0) {
            	encodeDataLen = encodeDataLen + (16 - remainDataLen);
            }
             
	        byte[] plaintext = new byte[encodeDataLen];
	        System.arraycopy(data, 0, plaintext, 0, data.length);
	        mCipher.init(Cipher.ENCRYPT_MODE, mKeySpec, mIV);
	        encode = mCipher.doFinal(plaintext);
        }
        catch(Exception except)
        {
        	except.printStackTrace();
        }
        
        return encode;
    }
}


