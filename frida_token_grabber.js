/**
 * Frida Hook 脚本 - 自动获取 Token
 * 
 * 功能：
 * 1. Hook OkHttp3/Retrofit 网络请求
 * 2. 拦截 authorization、club-id、role-id、tenant-id
 * 3. 自动保存到文件供 Kivy APP 读取
 */

console.log("[*] Frida Token Grabber 已加载");

// 配置
const TARGET_HOST = "dysh.dyswl.com";
const TOKEN_FILE = "/sdcard/grab_order_token.json";

// Token 存储
var tokenData = {
    token: "",
    clubId: "",
    roleId: "",
    tenantId: "",
    lastUpdate: 0
};

// 保存 Token 到文件
function saveToken() {
    var File = Java.use("java.io.File");
    var FileWriter = Java.use("java.io.FileWriter");
    
    try {
        var file = File.$new(TOKEN_FILE);
        var writer = FileWriter.$new(file);
        
        var data = JSON.stringify({
            token: tokenData.token,
            club_id: tokenData.clubId,
            role_id: tokenData.roleId,
            tenant_id: tokenData.tenantId,
            timestamp: Date.now()
        });
        
        writer.write(data);
        writer.close();
        
        console.log("[✓] Token 已保存: " + TOKEN_FILE);
        
        // 发送到 Python 端
        send({
            type: "token_update",
            data: {
                token: tokenData.token,
                club_id: tokenData.clubId,
                role_id: tokenData.roleId,
                tenant_id: tokenData.tenantId
            }
        });
        
    } catch (e) {
        console.log("[!] 保存 Token 失败: " + e);
    }
}

// Hook OkHttp3
function hookOkHttp3() {
    try {
        var Request = Java.use("okhttp3.Request");
        var Headers = Java.use("okhttp3.Headers");
        
        // Hook Request.Builder.build()
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        
        RequestBuilder.build.implementation = function() {
            var request = this.build();
            
            try {
                var url = request.url().toString();
                
                // 只处理目标域名
                if (url.indexOf(TARGET_HOST) !== -1) {
                    var headers = request.headers();
                    
                    var token = headers.get("authorization");
                    var clubId = headers.get("club-id");
                    var roleId = headers.get("role-id");
                    var tenantId = headers.get("tenant-id");
                    
                    var updated = false;
                    
                    if (token && token !== tokenData.token) {
                        tokenData.token = token.replace("Bearer ", "").trim();
                        updated = true;
                        console.log("[Token] " + tokenData.token.substring(0, 20) + "...");
                    }
                    
                    if (clubId && clubId !== tokenData.clubId) {
                        tokenData.clubId = clubId;
                        updated = true;
                        console.log("[Club-ID] " + clubId);
                    }
                    
                    if (roleId && roleId !== tokenData.roleId) {
                        tokenData.roleId = roleId;
                        updated = true;
                        console.log("[Role-ID] " + roleId);
                    }
                    
                    if (tenantId && tenantId !== tokenData.tenantId) {
                        tokenData.tenantId = tenantId;
                        updated = true;
                        console.log("[Tenant-ID] " + tenantId);
                    }
                    
                    // 有更新时保存
                    if (updated) {
                        saveToken();
                    }
                }
            } catch (e) {
                console.log("[!] 处理请求时出错: " + e);
            }
            
            return request;
        };
        
        console.log("[✓] OkHttp3 Hook 成功");
        
    } catch (e) {
        console.log("[!] OkHttp3 Hook 失败: " + e);
    }
}

// Hook Retrofit（如果使用）
function hookRetrofit() {
    try {
        var ServiceMethod = Java.use("retrofit2.ServiceMethod");
        
        ServiceMethod.invoke.implementation = function(args) {
            var result = this.invoke(args);
            console.log("[Retrofit] 请求发送");
            return result;
        };
        
        console.log("[✓] Retrofit Hook 成功");
        
    } catch (e) {
        console.log("[!] Retrofit Hook 失败（可能未使用 Retrofit）");
    }
}

// Hook HttpURLConnection（兜底方案）
function hookHttpURLConnection() {
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            if (key.toLowerCase() === "authorization" && value.indexOf(TARGET_HOST) !== -1) {
                var token = value.replace("Bearer ", "").trim();
                if (token !== tokenData.token) {
                    tokenData.token = token;
                    console.log("[Token] " + token.substring(0, 20) + "...");
                    saveToken();
                }
            }
            
            return this.setRequestProperty(key, value);
        };
        
        console.log("[✓] HttpURLConnection Hook 成功");
        
    } catch (e) {
        console.log("[!] HttpURLConnection Hook 失败: " + e);
    }
}

// 启动 Hook
Java.perform(function() {
    console.log("[*] 开始 Hook 网络请求...");
    
    // 延迟一点确保类加载
    setTimeout(function() {
        hookOkHttp3();
        hookRetrofit();
        hookHttpURLConnection();
        
        console.log("[✓] 所有 Hook 已激活");
        console.log("[*] 等待目标 APP 发送网络请求...");
    }, 1000);
});

// 处理来自 Python 的消息
rpc.exports = {
    getToken: function() {
        return tokenData;
    },
    
    clearToken: function() {
        tokenData = {
            token: "",
            clubId: "",
            roleId: "",
            tenantId: "",
            lastUpdate: 0
        };
        return true;
    }
};

