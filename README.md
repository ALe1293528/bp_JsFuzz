# JsFuzz

Burp Suite 被动扫描插件，基于 `https://github.com/InitRoot/BurpJSLinkFinder` 二开，并加入了一些便利的功能

## 功能
- **JS 接口发现**：原 LinkFinder 正则 + fetch / axios / XMLHttpRequest / jQuery / GraphQL / WebSocket / REST 识别
- **URL 还原**：相对 / 绝对 / 协议相对 / CDN 路径自动补全为绝对地址
- **存活检测**：HEAD→GET，2xx-3xx=Alive / 404=Dead / 其余=Unknown
- **未授权检测**：未登录重放、IDOR（id±1/随机）、敏感数据返回
- **API Fuzz**：9 类策略，固定线程池并发 20，逐条记录请求/响应

## 加载
Burp → Extensions → Add → 类型选 **Java** → 选 `js-api-hunter-pro.jar`，
出现 **JsFuzz** 标签页。浏览目标让 `.js` 经过 Burp 即自动扫描。

## TODO
- 加入主动扫描功能
- 加入过滤器，只扫描选定 host 的 js 文件