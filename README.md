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
[httpclient工具类](https://github.com/wjy060708/httpclientutil)
实现跨域发送请求 包括http/http+ssl get/post 提交表单、代理等

	public class SimpleHttpClientDemo {

	/**
	 * 
	 * @param url url地址
	 * @param map 请求参数
	 * @param encoding 编码
	 * @return
	 * @throws IOException 
	 * @throws ClientProtocolException 
	 */
	public static String doPost(String url, Map<String, String> map,String encoding) throws         ClientProtocolException, IOException {
		
		String body = "";
		//创建httpclient对象
		CloseableHttpClient client = HttpClients.createDefault();
		
		//创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		//装填参数
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		if(map!=null){
			for (Entry<String, String> entry : map.entrySet()) {
				nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
			}
		}
		
		//设置参数到请求对象中
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, encoding));
		
		System.out.println("请求地址："+url);
		System.out.println("请求参数："+nvps.toString());
		
		//设置header信息
		//指定报文头【Content-type】、【User-Agent】
		httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpPost.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
		
		//执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		//获取结果实体
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			//按指定编码转换结果实体为String类型
			body = EntityUtils.toString(entity, encoding);
		}
		EntityUtils.consume(entity);
		//释放链接
		response.close();
        return body;
	}
	
	/**
	 * 发送 get请求
	 */
	public static String doGet(String url, Map<String, String> map,String encoding) {
		
		CloseableHttpClient httpclient = HttpClients.createDefault();
		
		HttpEntity entity;
		try {
			
			URIBuilder uriBuilder = new URIBuilder(url);
			// 创建httpget.  
			HttpGet httpget = new HttpGet(url);
			
			//装填参数
			List<NameValuePair> nvps = new ArrayList<NameValuePair>();
			if(map!=null){
				for (Entry<String, String> entry : map.entrySet()) {
					nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
				}
			}
			uriBuilder.setParameters(nvps);
			// 根据带参数的URI对象构建GET请求对象
	        HttpGet httpGet = new HttpGet(uriBuilder.build());
	        
	        // 浏览器表示
	        httpGet.addHeader("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.6)");
	        // 传输的类型
	        httpGet.addHeader("Content-Type", "application/x-www-form-urlencoded");
			
			// 执行get请求.  
			CloseableHttpResponse response = httpclient.execute(httpget);
			try {
				// 获取响应实体  
				entity = response.getEntity();
				System.out.println("--------------------------------------");
				// 打印响应状态  
				System.out.println(response.getStatusLine());
				if (entity != null) {
					// 打印响应内容长度  
					System.out.println("Response content length: " + entity.getContentLength());
					// 打印响应内容  
					System.out.println("Response content: " + EntityUtils.toString(entity));
					
					return entity.toString();
				}
				System.out.println("------------------------------------");
				
				return null;
			} finally {
				response.close();
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} finally {
			// 关闭连接,释放资源  
			try {
				httpclient.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
       }

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
#### 4.4.1思路
    1.利用密钥和ip地址验证token是否正确，并得到userId
    2.用userid检查redis中是否有用户信息，如果有则延长它的时间
    3.登录状态返回
#### 4.4.2认证service层代码
    public UserInfo verify(String userId){
    // 去缓存中查询是否有redis
    Jedis jedis = redisUtil.getJedis();
    String key = userKey_prefix+userId+userinfoKey_suffix;
    String userJson = jedis.get(key);
    // 延长时效
    jedis.expire(key,userKey_timeOut);
    if (userJson!=null){
        UserInfo userInfo = JSON.parseObject(userJson, UserInfo.class);
        return  userInfo;
    }
    return  null;
    }
#### 4.4.3认证controller层代码
    String token = request.getParameter("token");
    String currentIp = request.getParameter("currentIp");
    // 检查token
   // Map<String, Object> map = JwtUtil.decode(token, signKey, currentIp);
    Map<String, Object> map = JwtUtil.decode(token, signKey, currentIp);
    if (map!=null){
        // 检查redis信息
        String userId = (String) map.get("userId");
        UserInfo userInfo = userInfoService.verify(userId);
        if (userInfo!=null){
            return "success";
        }
    }
    return "fail";
    }
### 4.5业务模块页面登录情况检查
#### 4.5.1认证中心签发的token如何保存
Token中
#### 4.5.2难道每一个模块都要做一个token的保存功能？
拦截器

    @Component
    public class AuthInterceptor extends HandlerInterceptorAdapter {
    
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getParameter("newToken");
        //把token保存到cookie
        if(token!=null){
            CookieUtil.setCookie(request,response,"token",token,WebConst.COOKIE_MAXAGE,false);
        }
        //获取cookie中的token
        if(token==null){
            token = CookieUtil.getCookieValue(request, "token", false);
        }

        if(token!=null) {
            //读取token
            Map map = getUserMapByToken(token);
            String nickName = (String) map.get("nickName");
            request.setAttribute("nickName", nickName);
        }
        return true;
    }
    private  Map getUserMapByToken(String  token){
        String tokenUserInfo = StringUtils.substringBetween(token, ".");
        Base64UrlCodec base64UrlCodec = new Base64UrlCodec();
        byte[] tokenBytes = base64UrlCodec.decode(tokenUserInfo);
        String tokenJson = null;
        try {
            tokenJson = new String(tokenBytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Map map = JSON.parseObject(tokenJson, Map.class);
        return map;
    }
    }
    
    public class CookieUtil {

    public static String getCookieValue(HttpServletRequest request, String cookieName, boolean isDecoder) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookieName == null){
            return null;
        }
        String retValue = null;
        try {
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equals(cookieName)) {
                    if (isDecoder) {//如果涉及中文
                        retValue = URLDecoder.decode(cookies[i].getValue(), "UTF-8");
                    } else {
                        retValue = cookies[i].getValue();
                    }
                    break;
                }
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return retValue;
    }


    public static   void setCookie(HttpServletRequest request, HttpServletResponse response, String cookieName, String cookieValue, int cookieMaxage, boolean isEncode) {
        try {
            if (cookieValue == null) {
                cookieValue = "";
            } else if (isEncode) {
                cookieValue = URLEncoder.encode(cookieValue, "utf-8");
            }
            Cookie cookie = new Cookie(cookieName, cookieValue);
            if (cookieMaxage >= 0)
                cookie.setMaxAge(cookieMaxage);
            if (null != request)// 设置域名的cookie
                cookie.setDomain(getDomainName(request));
            cookie.setPath("/");
            response.addCookie(cookie);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    /**
     * 得到cookie的域名
     */
    private static final String getDomainName(HttpServletRequest request) {
        String domainName = null;

        String serverName = request.getRequestURL().toString();
        if (serverName == null || serverName.equals("")) {
            domainName = "";
        } else {
            serverName = serverName.toLowerCase();
            serverName = serverName.substring(7);
            final int end = serverName.indexOf("/");
            serverName = serverName.substring(0, end);
            final String[] domains = serverName.split("\\.");
            int len = domains.length;
            if (len > 3) {
                // www.xxx.com.cn
                domainName = domains[len - 3] + "." + domains[len - 2] + "." + domains[len - 1];
            } else if (len <= 3 && len > 1) {
                // xxx.com or xxx.cn
                domainName = domains[len - 2] + "." + domains[len - 1];
            } else {
                domainName = serverName;
            }
        }

        if (domainName != null && domainName.indexOf(":") > 0) {
            String[] ary = domainName.split("\\:");
            domainName = ary[0];
        }
        System.out.println("domainName = " + domainName);
        return domainName;
    }
    }
#### 4.5.3如何区分请求是否一定要登录？ 
    自定义注解
    
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface LoginRequire {

        boolean autoRedirect() default true;
    }
    
    首先这个验证功能是每个模块都要有的，也就是所有web模块都需要的。在每个controller方法进入前都需要进行检查。可以利用     在springmvc中的拦截器功能。
    
    @Configuration
    public class WebMvcConfiguration extends WebMvcConfigurerAdapter{
    @Autowired
    AuthInterceptor authInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry){
        registry.addInterceptor(authInterceptor).addPathPatterns("/**");
        super.addInterceptors(registry);
    }
    }
    
    package com.wangjinyin.gmall.config;

    import java.io.UnsupportedEncodingException;
    import java.net.URLEncoder;
    import java.util.Map;

    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;

    import org.apache.commons.lang3.StringUtils;
    import org.springframework.stereotype.Component;
    import org.springframework.web.method.HandlerMethod;
    import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

    import com.alibaba.fastjson.JSON;

    import io.jsonwebtoken.impl.Base64UrlCodec;

    //定义拦截器
    @Component
    public class AuthInterceptor extends HandlerInterceptorAdapter {

	 // 进入控制器之前，执行！ 
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //登录的时候 将token 写入cookie
        String token = request.getParameter("newToken");
        System.out.println("newToken" + token);
        // 写cookie！
        if (token!=null){
            // 使用cookie 的工具类
            CookieUtil.setCookie(request,response,"token",token,WebConst.cookieMaxAge,false);
        }
        // 当访问非登录模块的时候，
        if (token==null){
            // 从cookie 中获取token
            token = CookieUtil.getCookieValue(request, "token", false);
        }

        // 当token 不为空的时候，获取用户昵称
        if (token!=null){
            // 解密token 得到用户昵称！
            Map map = getUserMapByToken(token);
            // 通过key nickName 获取用户昵称
            String nickName = (String) map.get("nickName");
            
            System.out.println("nickName = " + nickName);
            //  保存作用域
            request.setAttribute("nickName",nickName);
        }
        
        // 知道方法上是否有注解@LoginRequire
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        // 获取请求的方法，并获取方法上的注解
        LoginRequire methodAnnotation = handlerMethod.getMethodAnnotation(LoginRequire.class);
        if (methodAnnotation!=null){
            // 开始准备认证 verify ();  在passport-web 中 web-util 访问 passport-web 跨域 ： @CrossOrigin， httpclient，jsonp
            // 获取salt
            String salt = request.getHeader("X-forwarded-for");
            // httpclient 远程调用 doget，dopost

            String result = HttpClientUtil.doGet(WebConst.VERIFY_URL + "?token=" + token + "&salt=" + salt);

            if ("success".equals(result)){
                // 保存用户Id
                Map map = getUserMapByToken(token);
                // 通过key nickName 获取用户昵称
                String userId = (String) map.get("userId");
                //  保存作用域
                request.setAttribute("userId",userId);
                // 用户登录进行放行！
                return true;
            }else {
                // 还需要看一下当前注解中的属性autoRedirect
                if (methodAnnotation.autoRedirect()){
                    // 跳转登录页面！
                    // http://passport.atguigu.com/index?originUrl=http%3A%2F%2Fitem.gmall.com%2F39.html
                    String requestURL  = request.getRequestURL().toString(); // http://item.gmall.com/39.html
                    // 进行编码
                    String encodeURL = URLEncoder.encode(requestURL, "UTF-8"); // http%3A%2F%2Fitem.gmall.com%2F39.html
                    // 页面跳转
                    response.sendRedirect(WebConst.LOGIN_URL+"?originUrl="+encodeURL);

                    return false;
                }
            }
        }
        return true;
    }

    // 解密token的
    private Map getUserMapByToken(String token) {
        // eyJhbGciOiJIUzI1NiJ9.eyJuaWNrTmFtZSI6IkF0Z3VpZ3UiLCJ1c2VySWQiOiIxIn0.XzRrXwDhYywUAFn-ICLJ9t3Xwz7RHo1VVwZZGNdKaaQ
        String ntoken = StringUtils.substringBetween(token, ".");
        
        // jwt通过base64 编码的，使用base64 发解码
        Base64UrlCodec base64UrlCodec = new Base64UrlCodec();
        // 字节数组
        byte[] decode = base64UrlCodec.decode(ntoken);
        // 字节数组，与map 集合转换，不能直接转换，将byte[] decode 变成字符串
        String mapStr = null;
        try {
            mapStr = new String(decode, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        Map map = JSON.parseObject(mapStr, Map.class);

        return map;


    }
    }
    以上方法，检查业务方法是否需要用户登录，如果需要就把cookie中的token和当前登录人的ip地址发给远程服务器进行登录验证，返回的result是验证结果true或者false。如果验证未登录，直接重定向到登录页面。

    
    
    
    




    
    


    
    
    
    


    

 
    

    
    

    
