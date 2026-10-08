/* Ultraviolet Config */
self.__uv$config = {
  prefix: '/service/',
  encodeUrl: (url) => {
    if (!url) return url;
    let result = '';
    for (let i = 0; i < url.length; i++) {
      result += i % 2 ? String.fromCharCode(url.charCodeAt(i) ^ 2) : url[i];
    }
    return encodeURIComponent(result);
  },
  decodeUrl: (url) => {
    if (!url) return url;
    const str = decodeURIComponent(url);
    let result = '';
    for (let i = 0; i < str.length; i++) {
      result += i % 2 ? String.fromCharCode(str.charCodeAt(i) ^ 2) : str[i];
    }
    return result;
  },
  handler: '/uv/uv.handler.js',
  client: '/uv/uv.client.js',
  bundle: '/uv/uv.bundle.js',
  config: '/uv/uv.config.js',
  sw: '/uv/uv.sw.js',
};
