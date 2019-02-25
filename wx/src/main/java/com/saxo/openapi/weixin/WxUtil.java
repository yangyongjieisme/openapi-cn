package com.saxo.openapi.weixin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;


/**
 * @author 
 * @date 2019/02/25
 * @desc 使用HTTPS方式访问连接
 */
public class WxUtil {

    private static Logger logger = LogManager.getLogger(WxUtil.class);

    //请求类型
    public static final String REQUEST_METHOD_GET = "GET";
    public static final String REQUEST_METHOD_POST = "POST";

    //================================微信第三方平台相关URL开始================================
    //详细参考:https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=&lang=zh_CN
    //获取预授权码
    public static String api_create_preauthcode_url = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=COMPONENT_ACCESS_TOKEN";
    public static String api_component_token_url = "https://api.weixin.qq.com/cgi-bin/component/api_component_token";
    //通过code换取网页授权access_token
    public static String get_access_token_bycode_url = "https://api.weixin.qq.com/sns/oauth2/component/access_token?appid=APPID&code=CODE&grant_type=authorization_code&component_appid=COMPONENT_APPID&component_access_token=COMPONENT_ACCESS_TOKEN";
    public static String api_query_auth_url = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=COMPONENT_ACCESS_TOKEN";
    //客服接口地址
    public static String send_message_url = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=ACCESS_TOKEN";
    //4、获取（刷新）授权公众号的令牌
    public static String api_authorizer_token_url = "https:// api.weixin.qq.com /cgi-bin/component/api_authorizer_token?component_access_token=COMPONENT_ACCESS_TOKEN";
    //5、获取授权方的账户信息
    public static String api_get_authorizer_info_url = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=COMPONENT_ACCESS_TOKEN";
    //6、获取授权方的选项设置信息
    public static String api_get_authorizer_option_url = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_option?component_access_token=COMPONENT_ACCESS_TOKEN";
    //7、设置授权方的选项信息
    public static String api_set_authorizer_option_url = "https://api.weixin.qq.com/cgi-bin/component/api_set_authorizer_option?component_access_token=COMPONENT_ACCESS_TOKEN";
    //微信分享URL
    public static String api_componentloginpage_url = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=COMPONENT_APPID&pre_auth_code=PRE_AUTH_CODE&redirect_uri=REDIRECT_URI";
    //================================微信第三方平台相关URL结束================================


    //================================微信公众号oauth2授权相关URL开始================================
    //详细参考:http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
    //用户同意授权，获取code
    public static String api_authorize_url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=APPID&redirect_uri=REDIRECT_URI&"
    		+ "response_type=code&scope=SCOPE&state=STATE#wechat_redirect";
    //通过code换取网页授权access_token
    public static String api_access_token_url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&"
    		+ "grant_type=authorization_code";
    //刷新access_token（如果需要）
    public static String api_refresh_token_url = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=APPID&grant_type=refresh_token&"
    		+ "refresh_token=REFRESH_TOKEN";
    //拉取用户信息(需scope为 snsapi_userinfo)
    public static String api_userinfo_url = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN"
    		+ "&openid=OPENID&lang=zh_CN";
    //================================微信公众号oauth2授权相关URL结束================================

   
    
   //=====================微信小程序開始==================
    
    public static String mini_api_login_url = "https://api.weixin.qq.com/sns/jscode2session";

  //=====================微信小程序關閉==================
    
    
    /**
     * @param requestUrl
     * @param method
     * @param paramDataStr
     * @return
     * @date 2016/12/29 18:00
     * @desc 采用HTTPS调用微信接口
     */
    public static String request(String requestUrl, String method, String paramDataStr) {
        logger.debug("=============================调用接口开始=============================");
        logger.debug("=============================接口URL： {} =============================",requestUrl);
        StringBuffer buffer = new StringBuffer();
        try {
        	MyX509TrustManager mm=new MyX509TrustManager();
            TrustManager[] tm = { mm };
            SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
            sslContext.init(null, tm, new SecureRandom());
            //创建sslfactory对象
            SSLSocketFactory ssf = sslContext.getSocketFactory();
            //创建URL对象
            URL url = new URL(requestUrl);
            HttpsURLConnection httpUrlConn = (HttpsURLConnection) url.openConnection();
            httpUrlConn.setSSLSocketFactory(ssf);
            //设置urlconn属性
            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            httpUrlConn.setUseCaches(false);

            if (WxUtil.REQUEST_METHOD_GET.equals(method)) {//GET请求
                httpUrlConn.setRequestMethod(WxUtil.REQUEST_METHOD_GET);
            } else {//POST请求
                httpUrlConn.setRequestMethod(WxUtil.REQUEST_METHOD_POST);
                httpUrlConn.setRequestProperty("Content-Type "," application/x-www-form-urlencoded ");
                httpUrlConn.setRequestProperty("accept", "*/*");
                httpUrlConn.setRequestProperty("connection", "Keep-Alive");
                httpUrlConn.setRequestProperty("user-agent","Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
                //以UTF-8编码写出参数
                OutputStream out = httpUrlConn.getOutputStream();
                out.write(paramDataStr.getBytes("UTF-8"));
                out.flush();
                out.close();

            }
            //打开连接
            httpUrlConn.connect();
            //读取返回内容
            InputStream inputStream = httpUrlConn.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "utf-8");
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            //读取全部返回内容到buffer
            String str = null;
            while ((str = bufferedReader.readLine()) != null) {
                buffer.append(str);
            }
            //关闭输入输出流，释放资源
            bufferedReader.close();
            inputStreamReader.close();
            inputStream.close();
            inputStream = null;
            httpUrlConn.disconnect();
            //返回结果
            return buffer.toString();
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * @date 2016/12/30 10:57
     * @desc 将xml形式字符串解析成map
     */
    
    public static Map<String,Object> parseXmlStrToMap(String xmlStr,String []keys) {
        Map<String,Object> map = new HashMap<String,Object>();
        logger.debug("====================xml数据为：{}====================",xmlStr);
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(xmlStr);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);
            Element root = document.getDocumentElement();
            NodeList nodeList = root.getChildNodes();
            Node node = null;
            for (String key : keys) {
                for (int i=0 ;i < nodeList.getLength() ;i++) {
                    node = nodeList.item(i);
                    if (node.getNodeName().equals(key)) {
                        map.put(key,node.getTextContent());
                        break;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("====================解析xml数字出现异常====================");
        }
        return map;
    }
/*
    public static JSONObject getUserInfo(String encryptedData, String sessionKey, String iv) {
		// 被加密的数据
		byte[] dataByte = Base64.decode(encryptedData);
		// 加密秘钥
		byte[] keyByte = Base64.decode(sessionKey);
		// 偏移量
		byte[] ivByte = Base64.decode(iv);
		try {
			// 如果密钥不足16位，那么就补足. 这个if 中的内容很重要
			int base = 16;
			if (keyByte.length % base != 0) {
				int groups = keyByte.length / base + (keyByte.length % base != 0 ? 1 : 0);
				byte[] temp = new byte[groups * base];
				Arrays.fill(temp, (byte) 0);
				System.arraycopy(keyByte, 0, temp, 0, keyByte.length);
				keyByte = temp;
			}
			// 初始化
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
			SecretKeySpec spec = new SecretKeySpec(keyByte, "AES");
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
			parameters.init(new IvParameterSpec(ivByte));
			cipher.init(Cipher.DECRYPT_MODE, spec, parameters);// 初始化
			byte[] resultByte = cipher.doFinal(dataByte);
			if (null != resultByte && resultByte.length > 0) {
				String result = new String(resultByte, "UTF-8");
				return JSON.parseObject(result);
			}
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			logger.error(e.getMessage(), e);
		} catch (InvalidParameterSpecException e) {
			logger.error(e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			logger.error(e.getMessage(), e);
		} catch (BadPaddingException e) {
			logger.error(e.getMessage(), e);
		} catch (UnsupportedEncodingException e) {
			logger.error(e.getMessage(), e);
		} catch (InvalidKeyException e) {
			logger.error(e.getMessage(), e);
		} catch (InvalidAlgorithmParameterException e) {
			logger.error(e.getMessage(), e);
		} catch (NoSuchProviderException e) {
			logger.error(e.getMessage(), e);
		}
		return null;
	}
	*/
}