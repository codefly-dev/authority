import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The edge serves this page at /auth/sign-in and its hashed assets under
// /auth/assets/, from the build output it embeds (code/signin.go), so the
// build writes straight into the Go package's out/ directory. The people who
// may sign in are not fetched: the edge renders them into index.html's
// `sign-in` data island when it serves the page.
export default defineConfig({
	plugins: [react()],
	base: "/auth/",
	build: {
		outDir: "../code/signin/out",
		emptyOutDir: true,
	},
});
