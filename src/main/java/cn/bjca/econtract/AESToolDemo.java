package cn.bjca.econtract;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES 加密工具（Demo）
 * @author econtract
 */
public class AESToolDemo {
	private static Logger logger = LoggerFactory.getLogger(AESToolDemo.class);
	/** 算法名称 */
	public static final String ALGORITHM = "AES";
	/** 加解密算法/模式/填充方式 */
	public static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";
	/** 秘钥长度 */
	public static final int KEYSIZE = 256;
	/** 编码格式 */
	public static final String ENCODING = "UTF-8";


	/** 示例用 secret */
	// TODO 如果您想直接使用此 demo 作为您的加密工具，请替换您的AppSecret
	static String appSecret = "71f6bb2d-728b-4a22-a8a9-e8149f3951a3";
	static String key = appSecret.replace("-", "");
	static String iv = key.substring(0, 16);
	/** 偏移量 */
	public static String IV = iv;
	/** 秘钥 */
	public static String KEY = key;

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    System.out.println("KEY"+key);
    System.out.println("IV"+iv);
	}

	/**
	 * 生成base64 key，作为加密和解密密钥且只有密钥相同解密加密才会成功
	 * @param specKey 256位(32字节)密钥
	 * @return
	 */
	public static String createKey(String specKey) {

		try {
			// 1.构造密钥生成器，指定为AES算法，不区分大小写
			KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM);
			// 2.根据specKey规则初始化密钥生成器，生成一个256位的随机源，根据传入的字节数组
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(specKey.getBytes(ENCODING));
			keygen.init(KEYSIZE, random);
			// 3.产生原始对称密钥
			SecretKey originalKey = keygen.generateKey();
			// 4.获得原始对称密钥的字节数组
			byte[] raw = originalKey.getEncoded();
			// 5.根据字节数组生成AES密钥
			SecretKey key = new SecretKeySpec(raw, ALGORITHM);
			// 6.对秘钥做Base64编码
			byte[] keyBase64 = Base64.encodeBase64(key.getEncoded());
			return new String(keyBase64, ENCODING);
		} catch (UnsupportedEncodingException e) {
			logger.error("Create key error", e);
			return null;
		} catch (NoSuchAlgorithmException e) {
			logger.error("Create key error", e);
			return null;
		}

	}
	/**
	 * 根据keyBase64构建Key对象
	 * @return
	 */
	public static Key getKey(String specKey) {
		try {
			String keyBase64 = createKey(specKey);
			byte[] keyByte = Base64.decodeBase64(keyBase64.getBytes(ENCODING));
			SecretKey key = new SecretKeySpec(keyByte, ALGORITHM);
			return key;
		} catch (UnsupportedEncodingException e) {
			logger.error("getKey error", e);
			return null;
		}

	}
	/**
	 * 根据keyBase64构建Key对象
	 * @return
	 */
	public static Key getKey() {
		return getKey(AESToolDemo.KEY);
	}

	/**
	 * 加密
	 * @param context 需要加密的明文
	 * @param key 加密用密钥
	 * @param iv 初始化向量IV(16位)
	 * @return
	 */
	public static byte[] encrypt(byte[] context, Key key, String iv) {
		try {
			logger.debug("java AES encrypt IV: " + iv);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
			// 初始化密码器，第一个参数为加密(ENCRYPT_MODE)操作，第二个参数为使用的KEY，第三个参数为初始化向量IV(16位)
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv.getBytes(ENCODING)));
			// 将加密并编码后的内容解码成字节数组
			byte[] result = cipher.doFinal(context);
			result = Base64.encodeBase64(result);

			//logger.debug("java AES encrypt: " + new String(result, ENCODING));

			return result;

		} catch (NoSuchAlgorithmException e) {
			logger.error("NoSuchAlgorithmException", e);
			return null;
		} catch (NoSuchPaddingException e) {
			logger.error("NoSuchPaddingException", e);
			return null;
		} catch (InvalidKeyException e) {
			logger.error("InvalidKeyException", e);
			return null;
		} catch (IllegalBlockSizeException e) {
			logger.error("IllegalBlockSizeException", e);
			return null;
		} catch (BadPaddingException e) {
			logger.error("BadPaddingException", e);
			return null;
		} catch (Exception e) {
			logger.error("encrypt error", e);
			return null;
		}
	}


	/** 解密
	 * @param result 加密后的密文byte数组
	 * @param key 解密用密钥
	 * @param iv 初始化向量IV(16位)
	 */
	public static byte[] decrypt(byte[] result, Key key, String iv) {

		byte[] context = null;
		Cipher cipher;
		try {
			logger.debug("java AES decrypt IV: " + iv);
			cipher = Cipher.getInstance(TRANSFORMATION, "BC");
			// 初始化密码器，第一个参数为解密(DECRYPT_MODE)操作，第二个参数为使用的KEY，第三个参数为初始化向量IV(16位)
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv.getBytes(ENCODING)));
			byte[] input = Base64.decodeBase64(result);
			// 将加密并编码后的内容解码成字节数组
			context = cipher.doFinal(input);

			//logger.debug("java AES decrypt: " + new String(context, ENCODING));

			return context;

		} catch (NoSuchAlgorithmException e) {
			logger.error("NoSuchAlgorithmException", e);
			return null;
		} catch (NoSuchPaddingException e) {
			logger.error("NoSuchPaddingException", e);
			return null;
		} catch (InvalidKeyException e) {
			logger.error("InvalidKeyException", e);
			return null;
		} catch (IllegalBlockSizeException e) {
			logger.error("IllegalBlockSizeException", e);
			return null;
		} catch (BadPaddingException e) {
			logger.error("BadPaddingException", e);
			return null;
		} catch (Exception e) {
			logger.error("decrypt error", e);
			return null;
		}
	}

  public static void main(String[] args) {
		// 获取秘钥
		Key key = AESToolDemo.getKey();
		// 用于测试加密方法的字符串
		String context ="{\"appId\":\"42ad0f2e349147d7bcb7d8fefbc556d9\",\"docId\":\"A322ACB7F2544977\",\"creditCode\":\"330781198509071995\",\"unCreditCode\":\"397e6b6c3898420aa8116f60f3aed803\",\"timestamp\":\"1557764561512\"}";
		System.out.println("===原文===" + context);

		// 加密
		byte[] encrypt = AESToolDemo.encrypt(context.getBytes(), key, AESToolDemo.IV);
		System.out.println("===加密===" + new String(encrypt));

		System.out.println("===加密串编码===" + URLEncoder.encode(new String(encrypt)));

		// 解密
		byte[] decrypt = AESToolDemo.decrypt(encrypt, key, AESToolDemo.IV);
		System.out.println("===解密===" + new String(decrypt));
  }
}
