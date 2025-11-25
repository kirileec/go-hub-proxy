package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	hubHost    = "registry-1.docker.io"
	authURL    = "https://auth.docker.io"
	blockedUAs = []string{"netcraft"}
	routes     map[string]string
	envUA      = os.Getenv("UA")
	envURL302  = os.Getenv("URL302")
	envURL     = os.Getenv("URL")
)

//go:embed assets/nginx.html
var NginxPage string

//go:embed assets/searchPage.html
var SearchPage string

func init() {
	routes = map[string]string{
		"quay":       "quay.io",
		"gcr":        "gcr.io",
		"k8s-gcr":    "k8s.gcr.io",
		"k8s":        "registry.k8s.io",
		"ghcr":       "ghcr.io",
		"cloudsmith": "docker.cloudsmith.io",
		"nvcr":       "nvcr.io",
		"test":       "registry-1.docker.io",
	}
}

func routeByHosts(host string) (string, bool) {
	if route, exists := routes[host]; exists {
		return route, false
	}
	return hubHost, true
}

func makeRes(body interface{}, status int, headers map[string]string) *http.Response {
	var respBody io.Reader

	switch b := body.(type) {
	case string:
		respBody = strings.NewReader(b)
	case []byte:
		respBody = bytes.NewReader(b)
	default:
		respBody = strings.NewReader(fmt.Sprintf("%v", b))
	}

	response := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(respBody),
		Header:     make(http.Header),
	}

	response.Header.Set("access-control-allow-origin", "*")

	for key, value := range headers {
		response.Header.Set(key, value)
	}

	return response
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(item, s) {
			return true
		}
	}
	return false
}

func getToken(repo string) (string, error) {
	tokenURL := fmt.Sprintf("%s/token?service=registry.docker.io&scope=repository:%s:pull", authURL, repo)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(tokenURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenData struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return "", err
	}

	return tokenData.Token, nil
}

func handleRequest(c *gin.Context) {
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))

	// 检查是否被屏蔽的爬虫
	if envUA != "" {
		additionalUA := strings.Split(regexp.MustCompile(`[	 |"'\r\n]+`).ReplaceAllString(envUA, ","), ",")
		blockedUAs = append(blockedUAs, additionalUA...)
	}

	if contains(blockedUAs, userAgent) && len(blockedUAs) > 0 {
		c.Data(http.StatusOK, "text/html; charset=UTF-8", []byte(NginxPage))
		return
	}

	// 获取查询参数
	ns := c.Query("ns")
	hubhost := c.Query("hubhost")
	host := c.Request.Host
	hostTop := strings.Split(host, ".")[0]

	var fakePage bool
	if ns != "" {
		if ns == "docker.io" {
			hubhost = hubHost
		} else {
			hubhost = ns
		}
	} else {
		var checkHost string
		checkHost, fakePage = routeByHosts(hostTop)
		hubhost = checkHost
	}

	fmt.Printf("subdomain [%s] -> %s 伪装页面: %v\n", hostTop, hubhost, fakePage)

	// 处理首页请求
	if c.Request.URL.Path == "/" {
		if envURL302 != "" {
			c.Redirect(http.StatusFound, envURL302)
			return
		} else if envURL != "" {
			if strings.ToLower(envURL) == "nginx" {
				c.Data(http.StatusOK, "text/html; charset=UTF-8", []byte(NginxPage))
				return
			} else {
				// 这里应该转发请求到指定URL，简化处理
				c.Redirect(http.StatusFound, envURL)
				return
			}
		} else {
			if fakePage {
				c.Data(http.StatusOK, "text/html; charset=UTF-8", []byte(SearchPage))
				return
			}
		}
	}

	// 处理搜索请求
	hubParams := []string{"/v1/search", "/v1/repositories"}
	if (strings.Contains(userAgent, "mozilla") || contains(hubParams, c.Request.URL.Path)) && !strings.HasPrefix(c.Request.URL.Path, "/v2/") {
		targetHost := "hub.docker.com"
		if strings.HasPrefix(c.Request.URL.Path, "/v1/") {
			targetHost = "index.docker.io"
		}

		// 构建目标URL
		targetURL := url.URL{
			Scheme:   "https",
			Host:     targetHost,
			Path:     c.Request.URL.Path,
			RawQuery: c.Request.URL.RawQuery,
		}

		// 转发请求
		client := &http.Client{}
		req, _ := http.NewRequest(c.Request.Method, targetURL.String(), c.Request.Body)
		req.Header = c.Request.Header.Clone()

		resp, err := client.Do(req)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// 复制响应
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	// 处理Docker Registry API请求
	targetURL := url.URL{
		Scheme: "https",
		Host:   hubHost,
		Path:   c.Request.URL.Path,
	}

	// 处理token请求
	if strings.Contains(c.Request.URL.Path, "/token") {
		tokenURL := authURL + c.Request.URL.Path + "?" + c.Request.URL.RawQuery
		client := &http.Client{}
		req, _ := http.NewRequest(c.Request.Method, tokenURL, c.Request.Body)

		// 复制必要的请求头
		req.Header.Set("User-Agent", c.GetHeader("User-Agent"))
		req.Header.Set("Accept", c.GetHeader("Accept"))
		req.Header.Set("Accept-Language", c.GetHeader("Accept-Language"))
		req.Header.Set("Accept-Encoding", c.GetHeader("Accept-Encoding"))
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "max-age=0")

		resp, err := client.Do(req)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// 复制响应
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}
		c.Status(resp.StatusCode)
		io.Copy(c.Writer, resp.Body)
		return
	}

	// 修改 /v2/ 请求路径
	if hubhost == "registry-1.docker.io" && regexp.MustCompile(`^/v2/[^/]+/[^/]+/[^/]+$`).MatchString(c.Request.URL.Path) &&
		!regexp.MustCompile(`^/v2/library`).MatchString(c.Request.URL.Path) {
		parts := strings.Split(strings.TrimPrefix(c.Request.URL.Path, "/v2/"), "/")
		if len(parts) >= 2 {
			targetURL.Path = "/v2/library/" + strings.Join(parts, "/")
		}
	}

	// 处理需要认证的请求
	if strings.HasPrefix(c.Request.URL.Path, "/v2/") &&
		(strings.Contains(c.Request.URL.Path, "/manifests/") ||
			strings.Contains(c.Request.URL.Path, "/blobs/") ||
			strings.Contains(c.Request.URL.Path, "/tags/") ||
			strings.HasSuffix(c.Request.URL.Path, "/tags/list")) {

		// 提取镜像名
		re := regexp.MustCompile(`^/v2/(.+?)(?:/(?:manifests|blobs|tags)/)`)
		matches := re.FindStringSubmatch(c.Request.URL.Path)
		if len(matches) > 1 {
			repo := matches[1]
			token, err := getToken(repo)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			// 构建带认证的请求
			client := &http.Client{}
			req, _ := http.NewRequest(c.Request.Method, targetURL.String()+"?"+c.Request.URL.RawQuery, c.Request.Body)

			// 设置请求头
			req.Header.Set("Host", hubHost)
			req.Header.Set("User-Agent", c.GetHeader("User-Agent"))
			req.Header.Set("Accept", c.GetHeader("Accept"))
			req.Header.Set("Accept-Language", c.GetHeader("Accept-Language"))
			req.Header.Set("Accept-Encoding", c.GetHeader("Accept-Encoding"))
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Cache-Control", "max-age=0")
			req.Header.Set("Authorization", "Bearer "+token)

			if c.GetHeader("X-Amz-Content-Sha256") != "" {
				req.Header.Set("X-Amz-Content-Sha256", c.GetHeader("X-Amz-Content-Sha256"))
			}

			resp, err := client.Do(req)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			// 复制响应头并修改认证相关头
			for key, values := range resp.Header {
				for _, value := range values {
					// 修改Www-Authenticate头
					if key == "Www-Authenticate" {
						value = strings.ReplaceAll(value, authURL, fmt.Sprintf("https://%s", c.Request.Host))
					}
					c.Header(key, value)
				}
			}

			// 处理重定向
			if resp.Header.Get("Location") != "" {
				location := resp.Header.Get("Location")
				fmt.Printf("Found redirection location, redirecting to %s\n", location)
				c.Redirect(http.StatusFound, location)
				return
			}

			c.Status(resp.StatusCode)
			io.Copy(c.Writer, resp.Body)
			return
		}
	}

	// 普通请求处理
	client := &http.Client{}
	req, _ := http.NewRequest(c.Request.Method, targetURL.String()+"?"+c.Request.URL.RawQuery, c.Request.Body)

	// 设置请求头
	req.Header.Set("Host", hubHost)
	req.Header.Set("User-Agent", c.GetHeader("User-Agent"))
	req.Header.Set("Accept", c.GetHeader("Accept"))
	req.Header.Set("Accept-Language", c.GetHeader("Accept-Language"))
	req.Header.Set("Accept-Encoding", c.GetHeader("Accept-Encoding"))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "max-age=0")

	if c.GetHeader("Authorization") != "" {
		req.Header.Set("Authorization", c.GetHeader("Authorization"))
	}

	if c.GetHeader("X-Amz-Content-Sha256") != "" {
		req.Header.Set("X-Amz-Content-Sha256", c.GetHeader("X-Amz-Content-Sha256"))
	}

	resp, err := client.Do(req)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 复制响应头并修改认证相关头
	for key, values := range resp.Header {
		for _, value := range values {
			// 修改Www-Authenticate头
			if key == "Www-Authenticate" {
				value = strings.ReplaceAll(value, authURL, fmt.Sprintf("https://%s", c.Request.Host))
			}
			c.Header(key, value)
		}
	}

	// 处理重定向
	if resp.Header.Get("Location") != "" {
		location := resp.Header.Get("Location")
		fmt.Printf("Found redirection location, redirecting to %s\n", location)
		c.Redirect(http.StatusFound, location)
		return
	}

	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func main() {
	r := gin.Default()
	r.Any("/*path", handleRequest)
	r.Run(":8080")
}
