# JsFuzz

Burp Suite 被动扫描插件，参考自 `https://github.com/InitRoot/BurpJSLinkFinder` ，加入了 fuzz 测试功能

## 功能
- **JS 接口发现**：原 LinkFinder 正则 + fetch / axios / XMLHttpRequest / jQuery / GraphQL / WebSocket / REST 识别
- **URL 还原**：相对 / 绝对 / 协议相对 / CDN 路径自动补全为绝对地址
- **存活检测**：HEAD→GET，2xx-3xx=Alive / 404=Dead / 其余=Unknown
- **未授权检测**：未登录重放、IDOR（id±1/随机）、敏感数据返回
- **API Fuzz**：9 类策略，固定线程池并发 20，逐条记录请求/响应

## TODO
- 加入主动扫描功能
- 加入过滤器，只扫描选定 host 的 js 文件
- 加入自定义 fuzz 字典功能