import { cp, mkdir, rm } from "node:fs/promises";

const destination = new URL("../dist/assets/", import.meta.url);
await rm(destination, { force: true, recursive: true });
await mkdir(destination, { recursive: true });
await cp(new URL("../assets/", import.meta.url), destination, { recursive: true });
