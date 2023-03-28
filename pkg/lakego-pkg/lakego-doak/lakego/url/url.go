package url

import (
    "net/url"
)

// 解析链接
func ParseURL(rawURL string) *URL {
    u := &URL{}
    u.url, _ = url.Parse(rawURL)
    u.query = u.url.Query()

    return u
}

type URL struct {
    url   *url.URL
    query url.Values
}

func (this *URL) AddQuery(name, value string) *URL {
    this.query.Add(name, value)

    return this
}

func (this *URL) AddQueries(queries map[string]string) *URL {
    for name, value := range queries {
        this.AddQuery(name, value)
    }

    return this
}

func (this *URL) GetQuery() url.Values {
    return this.query
}

func (this *URL) GetURL() *url.URL {
    return this.url
}

func (this *URL) Build() *url.URL {
    this.url.RawQuery = this.query.Encode()

    return this.url
}

func (this *URL) BuildString() string {
    return this.Build().String()
}
