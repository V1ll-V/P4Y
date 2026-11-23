import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "P4Y",
  displayVersion: "v0.92",
  version: packageJson.version,
  copyright: `© ${currentYear}, P4Y.`,
  meta: {
    title: "P4Y 智能攻防系统控制台",
    description: "LLM 驱动的 CTF 解题与自主网络攻防系统控制台",
  },
};
