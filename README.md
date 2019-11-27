# SpringBoot SSO单点登录笔记
## 1.SSO单点登录概念：
    单点登录是目前流行的企业业务整合的解决方案之一。SSO的定义是在多个引用系统中用户只需要登录一次就可以访问
    所有相互信任的应用系统。
    例如：一个大旅游景点有很多小的景点需要单独购票，很多游客需要游玩所有的景点，这种买票的方式很不方便，需要在每个景点门 口排队买票，钱包拿进拿出的很不安全。于是绝大多数游客选在在大门买一张通票(也叫套票),就可以玩遍所有景点儿不需要重新再买     票。他们只需要在每个景点门口出示一下套票就能够被允许进入每个独立的景点了。
![maze](https://github.com/wjy060708/SSO-/blob/master/%E5%9B%BE%E7%89%871.png)
## 2.为什么要使用SSO单点登录
    随着网站的不断壮大，一个应用会按照功能模块拆分为多个服务进行开发，做SOA服务（Dobbo、springCloud），服务与服务之间、或者系统与系统之间都是通过HTTP或者restful来进行通信的。
    在以往的单体应用中将登录信息存储在session中，需要时随时获取，如果取不到则跳转到登录页面进行登录。但在如今的分布式应用中如何实现session之间的共享？
    目前较流行的解决方案为SSO与redis:
## 3.跨域
### 3.1 httpclient
### 3.2 Spring Boot跨域(@CrossOrigin)
## 4. SSO实现两个功能
### 4.1 SSO登录和认证功能
    整个应用共同拥有一个认证中心，只有认证中心才能接受用户的用户名和密码等信息进行认证，其他系统不提供登录入口，只接受认证中心的间接授权。间接授权通过令牌实现，当用户提供的用户名和密码通过认证中心认证后，认证中心会创建授权令牌，在接下来的跳转过程中，授权令牌作为参数发送给各个子系统，子系统拿到令牌即得到了授权，然后创建局部会话。
### 4.2 流程图：
![maze](https://github.com/wjy060708/SSO-/blob/master/%E5%9B%BE%E7%89%872.png)
### 4.3登录解析
#### 4.3.1思路
    1.当用户访问某个模块或者页面时先检查**cookie中是否有token** 如没有则跳转到登录页面
    2.将用户信息加载到写入redis，redis中有该用户视为登录状态
    3.用userId+当前用户登录ip地址(nginx配置)+密钥生成token
    4.重定向用户到之前的来源地址，同时把token作为参数附上
#### 4.3.2登录service层代码
    public String userKey_prefix="user:";
    public String userinfoKey_suffix=":info";
    public int userKey_timeOut=60*60*24;


    @Override
    public UserInfo login(UserInfo userInfo) {
        //对密码进行加密
        String password = DigestUtils.md5DigestAsHex(userInfo.getPasswd().getBytes());
        userInfo.setPasswd(password);
        //
        UserInfo info = userInfoMapper.selectOne(userInfo);

        if (info!=null){
            // 获得到redis ,将用户存储到redis中
            Jedis jedis = redisUtil.getJedis();
            jedis.setex(userKey_prefix+info.getId()+userinfoKey_suffix,userKey_timeOut, JSON.toJSONString(info));
            jedis.close();
            return  info;
        }
        return null;
    }
#### 4.3.3生成token
    jwt生成token（Json Web Token）工具
    1.原理：JWT（Json Web Token） 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准。
    JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源。
    2.作用：JWT 最重要的作用就是对 token信息的防伪作用。
    3.原理：一个JWT由三个部分组成：公共部分、私有部分、签名部分。最后由这三者组合进行base64编码得到JWT。
![maze](https://github.com/wjy060708/SSO-/blob/master/%E5%9B%BE%E7%89%873.png)

        公用部分：主要是该JWT的相关配置参数，比如签名的加密算法、格式类型、过期时间等等。
        Key=WANGJINYIN
        私有部分：用户自定义的内容，根据实际需要真正要封装的信息。如：userInfo 
        签名部分：Salt  iP: 当前服务器的Ip地址!{linux 中配置代理服务器的ip}主要用户对JWT生成字符串的时候，进行加密{盐值}
        最终组成 key+salt+userInfo  token!
        base64编码，并不是加密，只是把明文信息变成了不可见的字符串。但是其实只要用一些工具就可以吧base64编码解成明文，     所以不要在JWT中放入涉及私密的信息，因为实际上JWT并不是加密信息。
    4.pom依赖
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.0</version>
    </dependency>
    5.token工具类
    public class JwtUtil {
    //生成token
    public static String encode(String key,Map<String,Object> param,String salt){
        if(salt!=null){
            key+=salt;
        }
        JwtBuilder jwtBuilder = Jwts.builder().signWith(SignatureAlgorithm.HS256,key);

        jwtBuilder = jwtBuilder.setClaims(param);

        String token = jwtBuilder.compact();
        return token;

    }
    //解析token
    public  static Map<String,Object>  decode(String token ,String key,String salt){
        Claims claims=null;
        if (salt!=null){
            key+=salt;
        }
        try {
            claims= Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        } catch ( JwtException e) {
           return null;
        }
        return  claims;
    }
}
#### 4.3.2登录controller代码
    @Value("${token.key}")
    String signKey;

    @RequestMapping("login")
    @ResponseBody
    public String login(HttpServletRequest request, UserInfo userInfo){
        // 取得ip地址 作为生成token的盐
        String remoteAddr  = request.getHeader("X-forwarded-for");
        if (userInfo!=null) {
            UserInfo loginUser = userInfoService.login(userInfo);
            if (loginUser == null) {
                return "fail";
            } else {
                // 生成token
                Map map = new HashMap();
                map.put("userId", loginUser.getId());
                map.put("nickName", loginUser.getNickName());
                String token = JwtUtil.encode(signKey, map, remoteAddr);
                return token;
            }
        }
        return "fail";
    }
### 4.4认证解析
功能：当业务模块某个页面要检查当前用户是否登录时，提交到认证中心，认证中心进行检查校验，返回登录状态、用户Id和用户名称。


    
    
    
    


    

 
    

    
    

    
