/** @type {import('next').NextConfig} */
module.exports = {
  async headers() {
    return [{ source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: "default-src 'self'; object-src 'none';" }] }];
  },
};
