package com.saxo.openapi.weixin;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * @author 
 * @date 
 * @desc 项目启动自动调用该服务完成微信access_token的获取或更新
 */
@Component
public class InitWxAccessTokenService {

    private static Logger logger = LogManager.getLogger(InitWxAccessTokenService.class);

//    @Resource
//    private WxAccesstokenMapper wxAccesstokenMapper;
//    @Resource
//    private WxOpenAccountMapper wxOpenAccountMapper;

    /**
     * @date 2016/12/30 13:34
     * @desc 生成微信的access_token，用于调用其他微信接口
     */
//    @PostConstruct
    public void generateWxAccessToken() {
//        logger.debug("========================{}生成微信access_token开始========================", CommonUtil.getCurrentDateTimeStr());
//        WxOpenAccount wxOpenAccount = wxOpenAccountMapper.findByAppId(GlobalConstant.appId);
//        String ticket = wxOpenAccount.getTicket();
//        WxAccesstoken wxAccesstoken = wxAccesstokenMapper.findByAppId(GlobalConstant.appId);
//        Date curDate = new Date();
//        //调用微信获取access_token接口获取更新的access_token
//        Map<String,Object> paramMap = new HashMap<String,Object>();
//        paramMap.put("component_appid",GlobalConstant.appId);
//        paramMap.put("component_appsecret",GlobalConstant.componentAppsecret);
//        paramMap.put("component_verify_ticket",wxOpenAccount.getTicket());
//        String resultStr = WxUtil.request(WxUtil.api_component_token_url,WxUtil.REQUEST_METHOD_POST, JSON.toJSONString(paramMap));
//        //调用微信结果
//        JSONObject resultObj = JSON.parseObject(resultStr);
//        if (wxAccesstoken != null) {//更新现有accessToken
//            wxAccesstoken.setUpdateTime(curDate);
//            wxAccesstoken.setAccessToken(resultObj.getString("component_access_token"));
//            wxAccesstoken.setExpiresIn(resultObj.getInteger("expires_in"));
//            wxAccesstokenMapper.updateByPrimaryKeySelective(wxAccesstoken);
//        } else {//保存accessToken
//            wxAccesstoken = new WxAccesstoken();
//            wxAccesstoken.setAppid(GlobalConstant.appId);
//            wxAccesstoken.setCreateTime(curDate);
//            wxAccesstoken.setUpdateTime(curDate);
//            wxAccesstoken.setAccessToken(resultObj.getString("component_access_token"));
//            wxAccesstoken.setExpiresIn(resultObj.getInteger("expires_in"));
//            wxAccesstokenMapper.insertSelective(wxAccesstoken);
//        }
    }
}