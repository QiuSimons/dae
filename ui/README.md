# daed Web UI

这个目录是 dae 的内置 Web UI 静态资源目录。

当前 UI 覆盖这些页面：

- `Dashboard`
- `Proxies`
- `Traffic`
- `Config`
- `Logs`

文件说明：

- `index.html`: 页面结构
- `styles.css`: 样式
- `script.js`: 控制器连接、实时流和交互逻辑
- `icons/*.svg`: 侧边栏图标

## 内置 WebUI 什么时候会启用

当前实现里，内置 WebUI 只有在下面几个条件同时满足时才会由 dae 挂载到 `/ui/`：

1. `global.external_controller` 已配置
2. `global.external_controller_secret` 非空
3. UI 静态资源在磁盘上可被 dae 找到

访问地址：

```text
http://<external_controller>/ui/
```

例如：

```text
http://10.0.0.253:9090/ui/
```

## UI 资源放哪里

dae 会按顺序查找 WebUI 目录。常用方式有三种：

1. 设置环境变量 `DAE_WEBUI_DIR=/path/to/ui`
2. 把整个 `ui/` 目录放到 `dae` 可执行文件旁边，或当前工作目录附近
3. 安装到共享目录：
   - `/usr/share/dae/ui`
   - `/usr/local/share/dae/ui`

对 OpenWrt / 路由器部署，最直接的方式就是：

```text
/usr/share/dae/ui/
```

这个目录下至少要有：

- `index.html`
- `styles.css`
- `script.js`

如果用了侧边栏图标，也要带上：

- `icons/`

## dae 配置示例

最小可用配置：

```dae
global {
  external_controller: "0.0.0.0:9090"
  external_controller_secret: "password"
}
```

如果只想监听本机，可以改成：

```dae
global {
  external_controller: "127.0.0.1:9090"
  external_controller_secret: "password"
}
```

## 如何安装

### 方式 1：直接随仓库运行

如果你是在这个仓库里运行 `dae`，并且当前工作目录或可执行文件附近能找到 `ui/`，dae 会自动发现它。

适合本地开发。

### 方式 2：安装到系统共享目录

把整个 `ui/` 目录复制到：

```bash
mkdir -p /usr/share/dae/ui
cp -r ui/* /usr/share/dae/ui/
```

适合打包、OpenWrt、systemd 服务和常规部署。

### 方式 3：显式指定目录

```bash
export DAE_WEBUI_DIR=/opt/dae/ui
dae run -c /etc/dae/config.dae
```

适合你不想把资源放到默认目录的时候。

## OpenWrt / 路由器示例

以 `10.0.0.253` 为例：

1. 确保 `config.dae` 里有：

```dae
global {
  external_controller: "0.0.0.0:9090"
  external_controller_secret: "password"
}
```

2. 把 UI 资源推到路由器：

```bash
scp -O -r ui root@10.0.0.253:/usr/share/dae/
```

3. 重启 dae：

```bash
ssh root@10.0.0.253 '/etc/init.d/dae restart'
```

4. 浏览器访问：

```text
http://10.0.0.253:9090/ui/#token=password
```

## 如何使用

### 内置模式

如果页面是通过 dae 自己提供的 `/ui/` 打开的：

- UI 会自动把 controller 地址识别成当前页面同源地址
- 推荐把 token 放在 URL fragment 里：

```text
http://127.0.0.1:9090/ui/#token=password
```

这样 token 不会出现在 HTTP 请求路径里。

### 独立静态文件模式

也可以单独把 `ui/` 当静态目录跑起来：

```bash
cd ui
python3 -m http.server 4173
```

然后访问：

```text
http://127.0.0.1:4173/
```

这种模式下需要：

- 手动在页面里输入 controller 和 token
- 或者把 controller 放进 query，把 token 放进 fragment

例如：

```text
http://127.0.0.1:4173/?controller=http://10.0.0.253:9090#token=password
```

## 认证方式

UI 使用 dae 的外部控制器鉴权：

- HTTP 请求：`Authorization: Bearer <token>`
- WebSocket 请求：`?token=<token>`

如果 token 错误，页面能打开，但接口不会连通。

## 当前使用到的接口

- `GET /version`
- `GET /configs`
- `PATCH /configs`
- `GET /configs/dae`
- `PUT /configs/dae`
- `GET /memory`
- `GET /traffic`
- `GET /connections`
- `GET /proxies`
- `PUT /proxies/{group}`
- `DELETE /proxies/{group}`
- `GET /proxies/{name}/delay`
- `GET /logs`

其中多项数据会优先通过 WebSocket 持续推送。

## 排障

### `/ui/` 是 404

通常是下面几种情况：

- 没配 `external_controller`
- 没配 `external_controller_secret`
- UI 资源目录没被 dae 找到

### 页面能打开，但一直没登录

优先检查：

- token 是否正确
- 访问地址是否用了正确端口
- 是否用了 `#token=...`
- dae 是否真的监听在 `external_controller` 上

### 修改了静态文件但页面没更新

如果是内置 `/ui/` 模式，更新静态文件后重启 dae 最稳妥：

```bash
/etc/init.d/dae restart
```

## 开发备注

- 内置 UI 路径固定是 `/ui/`
- 直接通过 `/ui/` 打开时，UI 会自动使用当前 origin 作为 controller
- token 可以来自：
  - 查询参数 `?token=...`
  - URL fragment `#token=...`
  - 本地存储

推荐优先使用 `#token=...`
